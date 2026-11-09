"""
penetration_testing.models
===========================

Shared, serializable data models used across every subsystem boundary.

These dataclasses are the *contract*. The security layer, module bridge,
intelligence layer, executor, evidence store and reporter all exchange these
exact types, which is what keeps the subsystem coherent rather than a bag of
loosely-typed dicts.

All models expose ``to_dict()`` for JSON/report serialization; the stateful
ones also expose ``from_dict()`` for session recovery.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .constants import (
    Confidence,
    EvidenceKind,
    Phase,
    Severity,
    SessionState,
    TaskState,
    ValidationStatus,
    VulnCategory,
)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _now() -> float:
    return time.time()


# ─────────────────────────────────────────────────────────────────────────────
# Target & scope
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Target:
    """An authorized assessment target as defined in config.xml.

    The scope manager treats this as immutable policy; nothing in the runtime
    may widen it.
    """

    identifier: str
    url: str                                    # primary URL (first in `urls`)
    domain: str                                 # derived from the primary URL
    urls: List[str] = field(default_factory=list)   # all authorized URLs
    allowed_domains: List[str] = field(default_factory=list)
    allow_wildcard_subdomains: bool = False
    allowed_protocols: List[str] = field(default_factory=lambda: ["https"])
    allowed_ports: List[int] = field(default_factory=lambda: [80, 443])
    allowed_paths: List[str] = field(default_factory=list)      # empty = all paths
    excluded_paths: List[str] = field(default_factory=list)
    excluded_hosts: List[str] = field(default_factory=list)
    permissions: Dict[str, bool] = field(default_factory=dict)
    max_requests_per_second: float = 2.0
    max_concurrency: int = 4

    def has_permission(self, capability: str) -> bool:
        """Authorization model for an offensive red-team engagement.

        A target in config.xml *is* the authorization. When no explicit
        ``permissions`` block is given, every capability (including active
        offensive ones) is granted — the operator put the URL in scope on
        purpose. When a ``permissions`` block IS given, it acts as an opt-in
        restriction and unlisted capabilities are denied.

        Scope is still fully enforced elsewhere (authorized domain confinement,
        public-IP-only resolution, rate limiting); this only governs which
        *capabilities* run, not which *targets* they may touch.
        """
        if not self.permissions:
            return True
        return bool(self.permissions.get(capability, False))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Evidence
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Evidence:
    """A single, integrity-stamped piece of evidence tied to the task that
    produced it. Stored separately from ordinary execution logs."""

    target_id: str
    task_id: str
    kind: EvidenceKind
    summary: str
    request: Optional[Dict[str, Any]] = None
    response_excerpt: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    evidence_id: str = field(default_factory=lambda: _new_id("ev"))
    timestamp: float = field(default_factory=_now)
    sha256: str = ""

    def __post_init__(self) -> None:
        if not self.sha256:
            self.sha256 = self.compute_hash()

    def compute_hash(self) -> str:
        h = hashlib.sha256()
        for part in (
            self.target_id, self.task_id, str(self.kind), self.summary,
            repr(self.request), self.response_excerpt or "", repr(self.data),
        ):
            h.update(str(part).encode("utf-8", "replace"))
        return h.hexdigest()

    def verify(self) -> bool:
        return self.sha256 == self.compute_hash()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["kind"] = str(self.kind)
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Findings
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    """A security observation with a strict validation state.

    Nothing may set ``validation_status = CONFIRMED`` without at least one
    supporting evidence id; :meth:`is_consistent` enforces that invariant and
    the analysis layer calls it before a finding is accepted.
    """

    target_id: str
    category: VulnCategory
    title: str
    description: str
    endpoint: str = ""
    technical_detail: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    reproduction: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    validation_status: ValidationStatus = ValidationStatus.POTENTIAL
    demonstrated_impact: str = ""
    potential_impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cwe: str = ""                                # e.g. "CWE-89"
    mitre: List[str] = field(default_factory=list)   # ATT&CK technique ids
    fp_reason: str = ""                          # why demoted/dropped, if any
    cvss_score: float = 0.0
    finding_id: str = field(default_factory=lambda: _new_id("find"))
    created_at: float = field(default_factory=_now)
    # Keeps the AI's reasoning auditable and separate from observed facts.
    ai_rationale: str = ""

    def is_consistent(self) -> bool:
        if self.validation_status == ValidationStatus.CONFIRMED:
            return len(self.evidence_ids) > 0
        return True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = str(self.category)
        d["severity"] = str(self.severity)
        d["confidence"] = str(self.confidence)
        d["validation_status"] = str(self.validation_status)
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Tasks
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Task:
    """A single planned unit of work routed through the module bridge."""

    phase: Phase
    capability: str                      # registry capability name
    description: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    state: TaskState = TaskState.PENDING
    result: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    attempts: int = 0
    task_id: str = field(default_factory=lambda: _new_id("task"))
    created_at: float = field(default_factory=_now)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None

    @property
    def duration(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return round(self.finished_at - self.started_at, 3)
        return None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["phase"] = str(self.phase)
        d["state"] = str(self.state)
        d["duration"] = self.duration
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Tool result — the normalized output every bridged module returns
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ToolResult:
    ok: bool
    capability: str
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_s: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Engagement session — the top-level stateful aggregate
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class EngagementSession:
    target_id: str
    state: SessionState = SessionState.CREATED
    tasks: List[Task] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    log: List[Dict[str, Any]] = field(default_factory=list)
    session_id: str = field(default_factory=lambda: _new_id("engage"))
    started_at: float = field(default_factory=_now)
    finished_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    # -- progress helpers used by the monitoring surface --
    def counts(self) -> Dict[str, int]:
        done = sum(1 for t in self.tasks if t.state == TaskState.COMPLETED)
        return {
            "tasks_total": len(self.tasks),
            "tasks_completed": done,
            "tasks_failed": sum(1 for t in self.tasks if t.state == TaskState.FAILED),
            "tasks_denied": sum(1 for t in self.tasks if t.state == TaskState.DENIED),
            "findings": len(self.findings),
            "confirmed": sum(
                1 for f in self.findings
                if f.validation_status == ValidationStatus.CONFIRMED
            ),
            "evidence": len(self.evidence),
        }

    def progress(self) -> float:
        if not self.tasks:
            return 0.0
        settled = sum(
            1 for t in self.tasks
            if t.state in (TaskState.COMPLETED, TaskState.FAILED,
                           TaskState.SKIPPED, TaskState.DENIED)
        )
        return round(100.0 * settled / len(self.tasks), 1)

    def add_log(self, level: str, message: str, **extra: Any) -> None:
        self.log.append(
            {"ts": _now(), "level": level, "message": message, **extra}
        )

    def to_dict(self, include_log: bool = False) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "session_id": self.session_id,
            "target_id": self.target_id,
            "state": str(self.state),
            "progress": self.progress(),
            "counts": self.counts(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "metadata": self.metadata,
            "tasks": [t.to_dict() for t in self.tasks],
            "findings": [f.to_dict() for f in self.findings],
            "evidence": [e.to_dict() for e in self.evidence],
        }
        if include_log:
            d["log"] = self.log
        return d
