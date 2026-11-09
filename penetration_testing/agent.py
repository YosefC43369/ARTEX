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
from .security.scope_manager import ScopeManager


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
            "active_sessions": active,
            "total_sessions": len(self._sessions),
        }

    # ── engagement lifecycle ─────────────────────────────────────────────────
    def start_engagement(self, target_id: str, background: bool = True) -> Dict[str, Any]:
        if target_id not in self.settings.targets:
            return {"error": "Unknown target (not in authorized scope).",
                    "target_id": target_id}

        orchestrator = self._build_orchestrator()
        session = EngagementSession(target_id=target_id)
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
