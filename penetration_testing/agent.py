"""
penetration_testing.agent
==========================

``PenetrationTestingAgent`` is the subsystem's public facade — the single class
``app.py`` instantiates and calls. It wires the components together (dependency
injection), manages engagement sessions and their lifecycle, and exposes a
small, stable API that returns plain serializable dicts.

Responsibilities
----------------
* Load & validate configuration on construction (fail-closed).
* Own the shared, stateless :class:`OpenRouterClient` (reuses the ARTEX
  ``OPENROUTER_API_KEY`` convention — no second provider config).
* Build an isolated component graph per engagement (fresh evidence chain and
  scope audit trail per session), run it synchronously or in a background
  thread, and keep a registry for status/report/cancel.
* Provide health/introspection so the host app can observe the subsystem.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional

from .configuration import Settings, load_settings
from .constants import SUBSYSTEM_NAME, SUBSYSTEM_VERSION, SessionState
from .evidence.evidence_store import EvidenceStore
from .exceptions import PenTestError
from .execution.executor import Executor
from .integration.module_bridge import ModuleBridge
from .intelligence.analysis import AnalysisEngine
from .intelligence.planner import Planner
from .llm_client import OpenRouterClient
from .models import EngagementSession
from .orchestrator import Orchestrator
from .reporting.reporter import Reporter
from .roles import RoleManager
from .intelligence.knowledge_base import KnowledgeBase
from .security.approval import ApprovalManager
from .security.scope_manager import ScopeManager
from .storage import AssetRegistry, FindingRegistry


class PenetrationTestingAgent:
    def __init__(
        self,
        config_path: Optional[str] = None,
        openrouter_api_key: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.logger = logger or logging.getLogger(SUBSYSTEM_NAME)
        # Fail-closed: a bad/missing config raises ConfigurationError here.
        self.settings: Settings = load_settings(config_path)
        self.llm = OpenRouterClient(openrouter_api_key, logger=self.logger)
        # Added capabilities ported from CyberStrikeAI (see docs gap analysis):
        self.roles = RoleManager()                 # role-based testing
        self.knowledge = KnowledgeBase(logger=self.logger)   # knowledge base
        self.approval = ApprovalManager()          # human-in-the-loop (shared)
        self.assets = AssetRegistry()              # asset management
        self.findings_registry = FindingRegistry() # vulnerability lifecycle
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        # A read-only bridge used purely for capability introspection.
        self._introspect = ModuleBridge(
            self.settings, ScopeManager(self.settings, self.logger),
            EvidenceStore(enabled=False), self.llm, self.logger,
        )
        self.logger.info("%s v%s initialized (%d target(s), LLM=%s)",
                         SUBSYSTEM_NAME, SUBSYSTEM_VERSION,
                         len(self.settings.targets), self.llm.available)

    # ── component factory (fresh, isolated graph per engagement) ─────────────
    def _build_orchestrator(self) -> Orchestrator:
        evidence = EvidenceStore(
            enabled=self.settings.evidence_enabled,
            persist_dir=self.settings.evidence_dir,
        )
        scope = ScopeManager(self.settings, self.logger)
        bridge = ModuleBridge(self.settings, scope, evidence, self.llm, self.logger)
        task_timeout = min(self.settings.limits.max_runtime_seconds, 180)
        executor = Executor(bridge, task_timeout=task_timeout, logger=self.logger)
        return Orchestrator(
            self.settings, scope, bridge, Planner(self.llm, self.logger),
            executor, AnalysisEngine(evidence, self.logger), evidence,
            self.llm, self.logger,
            approval=self.approval, knowledge=self.knowledge,
        )

    # ── introspection ────────────────────────────────────────────────────────
    def list_targets(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self.settings.targets.values()]

    def list_capabilities(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._introspect.list_capabilities(available_only=False)]

    def health(self) -> Dict[str, Any]:
        with self._lock:
            active = sum(
                1 for e in self._sessions.values()
                if e["session"].state in (SessionState.RUNNING, SessionState.PLANNING)
            )
        return {
            "subsystem": SUBSYSTEM_NAME,
            "version": SUBSYSTEM_VERSION,
            "status": "healthy",
            "config_loaded": True,
            "targets": len(self.settings.targets),
            "llm_available": self.llm.available,
            "capabilities_available": len(self._introspect.list_capabilities()),
            "autonomous_enabled": self.settings.autonomous_enabled,
            "roles": len(self.roles.list_roles()),
            "knowledge_entries": len(self.knowledge),
            "pending_approvals": len(self.approval.pending()),
            "assets": self.assets.stats().get("total", 0),
            "vulnerabilities": self.findings_registry.stats().get("total", 0),
            "active_sessions": active,
            "total_sessions": len(self._sessions),
        }

    # ── engagement lifecycle ─────────────────────────────────────────────────
    def start_engagement(self, target_id: str, role: Optional[str] = None,
                         background: bool = True) -> Dict[str, Any]:
        if target_id not in self.settings.targets:
            return {"error": "Unknown target (not in authorized scope).",
                    "target_id": target_id}
        try:
            role_obj = self.roles.get(role)
        except KeyError:
            return {"error": f"Unknown role: {role}"}

        orchestrator = self._build_orchestrator()
        orchestrator.role = role_obj
        session = EngagementSession(target_id=target_id)
        session.metadata["role"] = role_obj.identifier
        with self._lock:
            self._sessions[session.session_id] = {
                "session": session, "orchestrator": orchestrator, "thread": None,
            }

        if background:
            thread = threading.Thread(
                target=self._run_safe, args=(orchestrator, target_id, session),
                daemon=True, name=f"pentest-{session.session_id[:8]}",
            )
            with self._lock:
                self._sessions[session.session_id]["thread"] = thread
            thread.start()
        else:
            self._run_safe(orchestrator, target_id, session)

        return {
            "session_id": session.session_id,
            "target_id": target_id,
            "role": role_obj.identifier,
            "state": str(session.state),
            "background": background,
        }

    def _run_safe(self, orchestrator: Orchestrator, target_id: str,
                  session: EngagementSession) -> None:
        try:
            orchestrator.run(target_id, session=session)
        except PenTestError as exc:
            session.state = SessionState.FAILED
            session.error = str(exc)
            session.add_log("error", f"Engagement crashed: {exc}")
        except Exception as exc:  # defensive: never leak a thread exception
            session.state = SessionState.FAILED
            session.error = f"unexpected: {exc}"
            self.logger.exception("Unexpected engagement failure")
        finally:
            # feed asset + vulnerability registries (cross-engagement inventory)
            try:
                self.assets.ingest_session(session)
                self.findings_registry.ingest(session.findings, session.session_id)
            except Exception:  # pragma: no cover - registry must never break a run
                self.logger.exception("Registry ingest failed")

    # ── status / results ─────────────────────────────────────────────────────
    def _entry(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._sessions.get(session_id)

    def get_status(self, session_id: str) -> Dict[str, Any]:
        entry = self._entry(session_id)
        if not entry:
            return {"error": "Unknown session_id."}
        s: EngagementSession = entry["session"]
        return {
            "session_id": s.session_id, "target_id": s.target_id,
            "state": str(s.state), "progress": s.progress(),
            "counts": s.counts(), "error": s.error,
            "started_at": s.started_at, "finished_at": s.finished_at,
        }

    def get_session(self, session_id: str, include_log: bool = False) -> Dict[str, Any]:
        entry = self._entry(session_id)
        if not entry:
            return {"error": "Unknown session_id."}
        return entry["session"].to_dict(include_log=include_log)

    def get_report(self, session_id: str,
                   formats: Optional[List[str]] = None) -> Dict[str, Any]:
        entry = self._entry(session_id)
        if not entry:
            return {"error": "Unknown session_id."}
        session: EngagementSession = entry["session"]
        target = self.settings.get_target(session.target_id)
        if target is None:
            return {"error": "Target no longer in configuration."}
        fmts = formats or self.settings.report_formats
        return Reporter(session, target).build(fmts)

    def cancel(self, session_id: str) -> Dict[str, Any]:
        entry = self._entry(session_id)
        if not entry:
            return {"error": "Unknown session_id."}
        entry["orchestrator"].cancel()
        return {"session_id": session_id, "cancelling": True}

    # ── ported features: roles / approvals / knowledge / registries ──────────
    def list_roles(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.roles.list_roles()]

    def list_pending_approvals(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return [a.to_dict() for a in self.approval.pending(session_id)]

    def decide_approval(self, approval_id: str, approve: bool = True) -> Dict[str, Any]:
        appr = self.approval.decide(approval_id, approve)
        if appr is None:
            return {"error": "Unknown or already-decided approval."}
        return appr.to_dict()

    def resume_engagement(self, session_id: str, background: bool = True) -> Dict[str, Any]:
        entry = self._entry(session_id)
        if not entry:
            return {"error": "Unknown session_id."}
        orchestrator: Orchestrator = entry["orchestrator"]
        session: EngagementSession = entry["session"]

        def _do():
            try:
                orchestrator.resume()
            except Exception:  # pragma: no cover
                self.logger.exception("Resume failed")
            finally:
                try:
                    self.assets.ingest_session(session)
                    self.findings_registry.ingest(session.findings, session.session_id)
                except Exception:  # pragma: no cover
                    pass

        if background:
            threading.Thread(target=_do, daemon=True,
                             name=f"ptresume-{session_id[:8]}").start()
        else:
            _do()
        return {"session_id": session_id, "resuming": True}

    def list_assets(self, kind: Optional[str] = None) -> Dict[str, Any]:
        assets = self.assets.by_kind(kind) if kind else self.assets.all()
        return {"assets": [a.to_dict() for a in assets], "stats": self.assets.stats()}

    def list_vulnerabilities(self, state: Optional[str] = None,
                             severity: Optional[str] = None,
                             category: Optional[str] = None) -> Dict[str, Any]:
        recs = self.findings_registry.filter(state=state, severity=severity,
                                             category=category)
        return {"vulnerabilities": [r.to_dict() for r in recs],
                "stats": self.findings_registry.stats()}

    def set_vulnerability_state(self, signature: str, state: str,
                               note: Optional[str] = None) -> Dict[str, Any]:
        try:
            rec = self.findings_registry.set_state(signature, state, note)
        except ValueError as exc:
            return {"error": str(exc)}
        if rec is None:
            return {"error": "Unknown finding signature."}
        return rec.to_dict()

    def knowledge_list(self) -> Dict[str, Any]:
        return {"entries": [e.to_dict() for e in self.knowledge.all()]}

    def knowledge_search(self, query: str) -> Dict[str, Any]:
        return {"results": [e.to_dict() for e in self.knowledge.search(query)]}

    def shutdown(self) -> None:
        """Cooperatively cancel all running engagements (for app shutdown)."""
        with self._lock:
            entries = list(self._sessions.values())
        for e in entries:
            try:
                e["orchestrator"].cancel()
            except Exception:  # pragma: no cover - best effort
                pass
        self.logger.info("%s shut down.", SUBSYSTEM_NAME)
