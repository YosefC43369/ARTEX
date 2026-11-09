"""
penetration_testing.security.approval
======================================

Human-in-the-loop (HITL) approval — an ARTEX port of CyberStrikeAI's approval
governance.

High-impact capabilities (active web testing, port scanning, API fuzzing by
default) require an explicit operator decision before the engagement will run
them. The orchestrator holds such tasks in ``AWAITING_APPROVAL`` and registers a
pending approval; an operator approves or rejects via the API; the engagement
can then be resumed to run the approved tasks.

This is a *governance gate layered on top of* scope enforcement — a capability
must already be granted by config.xml AND approved here before it runs. Approval
never widens scope; it only withholds already-permitted-but-sensitive actions
until a human signs off.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from ..constants import DEFAULT_APPROVAL_CAPABILITIES


@dataclass
class Approval:
    session_id: str
    target_id: str
    capability: str
    state: str = "pending"             # pending | approved | rejected
    approval_id: str = field(default_factory=lambda: "appr_" + uuid.uuid4().hex[:12])
    created_at: float = field(default_factory=time.time)
    decided_at: Optional[float] = None
    decided_by: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "approval_id": self.approval_id, "session_id": self.session_id,
            "target_id": self.target_id, "capability": self.capability,
            "state": self.state, "created_at": self.created_at,
            "decided_at": self.decided_at, "decided_by": self.decided_by,
        }


class ApprovalManager:
    def __init__(self, required: Optional[Set[str]] = None):
        self.required: Set[str] = (
            set(required) if required is not None
            else set(DEFAULT_APPROVAL_CAPABILITIES))
        self._approvals: Dict[str, Approval] = {}
        self._lock = threading.Lock()

    def requires_approval(self, capability: str) -> bool:
        return capability in self.required

    def _key(self, session_id: str, capability: str) -> str:
        return f"{session_id}::{capability}"

    def request(self, session_id: str, target_id: str, capability: str) -> Approval:
        """Register (idempotently) a pending approval for a held capability."""
        with self._lock:
            for a in self._approvals.values():
                if a.session_id == session_id and a.capability == capability:
                    return a
            appr = Approval(session_id=session_id, target_id=target_id,
                            capability=capability)
            self._approvals[appr.approval_id] = appr
            return appr

    def is_approved(self, session_id: str, capability: str) -> bool:
        if capability not in self.required:
            return True  # not gated -> implicitly allowed
        with self._lock:
            for a in self._approvals.values():
                if (a.session_id == session_id and a.capability == capability
                        and a.state == "approved"):
                    return True
        return False

    def decide(self, approval_id: str, approve: bool,
               by: str = "operator") -> Optional[Approval]:
        with self._lock:
            appr = self._approvals.get(approval_id)
            if appr is None or appr.state != "pending":
                return None
            appr.state = "approved" if approve else "rejected"
            appr.decided_at = time.time()
            appr.decided_by = by
            return appr

    def pending(self, session_id: Optional[str] = None) -> List[Approval]:
        with self._lock:
            return [a for a in self._approvals.values()
                    if a.state == "pending"
                    and (session_id is None or a.session_id == session_id)]

    def for_session(self, session_id: str) -> List[Approval]:
        with self._lock:
            return [a for a in self._approvals.values() if a.session_id == session_id]

    def approved_capabilities(self, session_id: str) -> Set[str]:
        with self._lock:
            return {a.capability for a in self._approvals.values()
                    if a.session_id == session_id and a.state == "approved"}
