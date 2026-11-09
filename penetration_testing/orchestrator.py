"""
penetration_testing.orchestrator
=================================

The bounded autonomous engagement loop — the component the directive's flow
diagram puts at the centre. It ties together scope, planning, execution,
analysis, evidence and reporting into one coherent, *terminating* workflow.

Consolidates ``orchestrator`` / ``workflow_engine`` / ``execution_loop`` /
``task_manager`` / ``lifecycle_manager`` / ``state_manager`` /
``session_manager`` / ``progress_tracker`` / ``event_manager`` /
``metrics_collector`` / ``health_monitor``.

Termination guarantees (no infinite loops, ever)
------------------------------------------------
The loop stops as soon as **any** bound trips:
* no more pending tasks, or
* ``max_iterations`` reached, or
* ``max_runtime_seconds`` elapsed, or
* ``max_tasks`` reached (also caps replanning), or
* cooperative cancellation requested.
"""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional

from .configuration import Settings
from .constants import Phase, SessionState, TaskState
from .evidence.evidence_store import EvidenceStore
from .exceptions import ExecutionCancelled, PenTestError, ScopeViolation
from .execution.executor import Executor
from .integration.module_bridge import ModuleBridge
from .intelligence.analysis import AnalysisEngine
from .intelligence.planner import Planner
from .llm_client import OpenRouterClient
from .models import EngagementSession, Target
from .reporting.reporter import Reporter
from .security.scope_manager import ScopeManager


class Orchestrator:
    def __init__(
        self,
        settings: Settings,
        scope: ScopeManager,
        bridge: ModuleBridge,
        planner: Planner,
        executor: Executor,
        analysis: AnalysisEngine,
        evidence: EvidenceStore,
        llm: OpenRouterClient,
        logger: Optional[logging.Logger] = None,
        role=None,
        approval=None,
        knowledge=None,
    ):
        self.settings = settings
        self.scope = scope
        self.bridge = bridge
        self.planner = planner
        self.executor = executor
        self.analysis = analysis
        self.evidence = evidence
        self.llm = llm
        self.logger = logger or logging.getLogger(__name__)
        self.role = role                 # optional roles.Role
        self.approval = approval         # optional security.approval.ApprovalManager
        self.knowledge = knowledge       # optional intelligence.KnowledgeBase
        self.session: Optional[EngagementSession] = None

    # ── lifecycle ────────────────────────────────────────────────────────────
    def cancel(self) -> None:
        self.executor.cancel()
        if self.session and self.session.state == SessionState.RUNNING:
            self.session.add_log("warning", "Cancellation requested.")

    def _permitted_capabilities(self, target: Target) -> List[str]:
        caps = []
        for spec in self.bridge.list_capabilities(available_only=True):
            if target.has_permission(spec.permission):
                caps.append(spec.name)
        if self.role is not None:
            # role narrows/orders — never widens — the permitted capabilities
            permitted = set(caps)
            ordered = [c for c in self.role.capabilities if c in permitted]
            ordered += [c for c in caps if c not in ordered]
            caps = ordered
        else:
            from .intelligence.planner import apply_default_order
            caps = apply_default_order(caps)
        return caps

    # ── main entry point ─────────────────────────────────────────────────────
    def run(
        self, target_identifier: str,
        session: Optional[EngagementSession] = None,
    ) -> EngagementSession:
        # 1. authorize (fail-closed) ------------------------------------------
        if session is None:
            session = EngagementSession(target_id=target_identifier)
        self.session = session
        try:
            target = self.scope.authorize_target(target_identifier)
        except ScopeViolation as exc:
            session.state = SessionState.FAILED
            session.error = str(exc)
            session.finished_at = time.time()
            session.add_log("error", f"Scope violation: {exc}")
            return session

        limits = self.settings.limits
        session.metadata["limits"] = limits.__dict__
        session.add_log("info", f"Engagement started for {target.identifier}")

        try:
            # 2. plan ----------------------------------------------------------
            session.state = SessionState.PLANNING
            caps = self._permitted_capabilities(target)
            if not caps:
                session.state = SessionState.COMPLETED
                session.finished_at = time.time()
                session.add_log("warning", "No permitted+available capabilities; nothing to do.")
                return self._finalize(session, target)

            session.tasks = self.planner.build_plan(target, caps, limits.max_tasks)
            session.add_log("info", f"Plan built with {len(session.tasks)} task(s)",
                            capabilities=caps)

            # 3. bounded execution loop ---------------------------------------
            session.state = SessionState.RUNNING
            self._execution_loop(session, target, caps)

            # 4. finalize ------------------------------------------------------
            return self._finalize(session, target)

        except ExecutionCancelled:
            session.state = SessionState.CANCELLED
            session.finished_at = time.time()
            session.add_log("warning", "Engagement cancelled.")
            return self._finalize(session, target, cancelled=True)
        except ScopeViolation as exc:
            session.state = SessionState.FAILED
            session.error = str(exc)
            session.finished_at = time.time()
            session.add_log("error", f"Scope violation: {exc}")
            return session
        except PenTestError as exc:
            session.state = SessionState.FAILED
            session.error = str(exc)
            session.finished_at = time.time()
            session.add_log("error", f"Engagement failed: {exc}")
            return session

    def _execution_loop(
        self, session: EngagementSession, target: Target, caps: List[str],
    ) -> None:
        started = time.monotonic()
        iterations = 0
        replanned = False

        while True:
            # -- bounds checks (terminate the loop) --
            if self.executor.cancelled:
                raise ExecutionCancelled("Cancelled during execution loop.")
            if iterations >= self.settings.limits.max_iterations:
                session.add_log("warning", "Max iterations reached; stopping.")
                break
            if time.monotonic() - started >= self.settings.limits.max_runtime_seconds:
                session.add_log("warning", "Max runtime reached; stopping.")
                break

            pending = [t for t in session.tasks if t.state == TaskState.PENDING]
            if not pending:
                break

            task = pending[0]
            iterations += 1

            # human-in-the-loop gate: hold high-impact capabilities for approval
            if (self.approval is not None
                    and self.approval.requires_approval(task.capability)
                    and not self.approval.is_approved(session.session_id, task.capability)):
                self.approval.request(session.session_id, target.identifier, task.capability)
                task.state = TaskState.AWAITING_APPROVAL
                session.add_log("warning",
                                f"{task.capability} held — awaiting human approval",
                                task_id=task.task_id)
                continue

            session.add_log("info", f"Executing {task.capability}",
                            task_id=task.task_id, iteration=iterations)

            result = self.executor.execute(task, target)
            if result.ok:
                findings = self.analysis.analyze_task(session, task, target)
                if self.knowledge is not None:
                    findings = [self.knowledge.enrich(f) for f in findings]
                session.findings.extend(findings)
                if findings:
                    session.add_log("info",
                                    f"{len(findings)} finding(s) from {task.capability}")

            # -- adaptive replan once, after recon has produced subdomains --
            if (not replanned and task.capability == "recon.subdomains"
                    and task.state == TaskState.COMPLETED):
                extra = self.planner.replan(
                    session, target, caps, self.settings.limits.max_tasks)
                if extra:
                    session.tasks.extend(extra)
                    session.add_log("info", f"Replanned: +{len(extra)} refined task(s)")
                replanned = True

        # mark any still-pending (stopped by bounds) as skipped
        for t in session.tasks:
            if t.state == TaskState.PENDING:
                t.state = TaskState.SKIPPED

    def _finalize(
        self, session: EngagementSession, target: Target, cancelled: bool = False,
    ) -> EngagementSession:
        # pull evidence collected by bridge/analysis into the session view
        summary = self.analysis.finalize(session, target)
        session.evidence = self.evidence.all()   # after modern detection records
        session.metadata["analysis_summary"] = summary
        session.metadata["evidence_chain"] = self.evidence.verify_chain()
        session.metadata["evidence_stats"] = self.evidence.stats()
        session.metadata["audit_log_size"] = len(self.scope.audit_log)

        if not cancelled and session.state == SessionState.RUNNING:
            session.state = SessionState.COMPLETED
        if session.finished_at is None:
            session.finished_at = time.time()
        session.add_log("info", f"Engagement {session.state}", **session.counts())
        return session

    # ── resume after human approval ──────────────────────────────────────────
    def resume(self) -> EngagementSession:
        """Re-run capabilities that were held for approval and are now approved."""
        session = self.session
        if session is None:
            raise PenTestError("No session to resume.")
        target = self.scope.authorize_target(session.target_id)

        promoted = 0
        for t in session.tasks:
            if t.state == TaskState.AWAITING_APPROVAL and (
                self.approval is None
                or self.approval.is_approved(session.session_id, t.capability)
            ):
                t.state = TaskState.PENDING
                promoted += 1

        if not promoted:
            session.add_log("info", "Resume: no newly-approved tasks to run.")
            return session

        session.add_log("info", f"Resume: {promoted} approved task(s) queued")
        session.state = SessionState.RUNNING
        caps = self._permitted_capabilities(target)
        self._execution_loop(session, target, caps)
        return self._finalize(session, target)

    # ── reporting convenience ────────────────────────────────────────────────
    def build_reports(self, formats: Optional[List[str]] = None) -> Dict[str, str]:
        if not self.session:
            return {}
        target = self.scope.settings.get_target(self.session.target_id)
        if target is None:  # pragma: no cover - session always has a valid target
            return {}
        fmts = formats or self.settings.report_formats
        return Reporter(self.session, target).build(fmts)
