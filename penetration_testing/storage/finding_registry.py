"""
penetration_testing.storage.finding_registry
=============================================

Vulnerability lifecycle management — an ARTEX port of CyberStrikeAI's
vulnerability-management concept.

Wraps engagement :class:`~penetration_testing.models.Finding` objects in records
that carry a lifecycle state, de-duplicates them across engagements by a stable
signature, and provides filtering and statistics. The analysis layer decides
*what* a finding is; this registry tracks *where it is in its lifecycle*.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Lifecycle states a finding moves through.
LIFECYCLE = ("open", "triaged", "confirmed", "resolved", "accepted_risk", "false_positive")


@dataclass
class FindingRecord:
    signature: str
    finding: Dict[str, Any]            # serialized Finding.to_dict()
    state: str = "open"
    first_session: str = ""
    occurrences: int = 1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature": self.signature, "state": self.state,
            "occurrences": self.occurrences, "first_session": self.first_session,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "notes": self.notes, "finding": self.finding,
        }


def _signature(finding: Dict[str, Any]) -> str:
    """Stable identity independent of the per-run finding_id."""
    return "|".join([
        str(finding.get("target_id", "")),
        str(finding.get("category", "")),
        str(finding.get("endpoint", "")),
        str(finding.get("title", "")),
    ])


class FindingRegistry:
    def __init__(self):
        self._records: Dict[str, FindingRecord] = {}
        self._lock = threading.Lock()

    # ── ingestion ────────────────────────────────────────────────────────────
    def ingest(self, findings: List[Any], session_id: str = "") -> Dict[str, int]:
        new, updated = 0, 0
        for f in findings:
            data = f.to_dict() if hasattr(f, "to_dict") else dict(f)
            sig = _signature(data)
            with self._lock:
                rec = self._records.get(sig)
                if rec:
                    rec.occurrences += 1
                    rec.last_seen = time.time()
                    rec.finding = data  # refresh to latest observation
                    updated += 1
                else:
                    # CONFIRMED findings start triaged; others start open.
                    start = ("confirmed"
                             if data.get("validation_status") == "confirmed"
                             else "open")
                    self._records[sig] = FindingRecord(
                        signature=sig, finding=data, state=start,
                        first_session=session_id)
                    new += 1
        return {"new": new, "updated": updated, "total": len(self._records)}

    # ── lifecycle ────────────────────────────────────────────────────────────
    def set_state(self, signature: str, state: str,
                  note: Optional[str] = None) -> Optional[FindingRecord]:
        if state not in LIFECYCLE:
            raise ValueError(f"Invalid lifecycle state: {state}")
        with self._lock:
            rec = self._records.get(signature)
            if rec is None:
                return None
            rec.state = state
            if note:
                rec.notes.append(f"[{time.strftime('%Y-%m-%d %H:%M')}] {note}")
            return rec

    # ── queries ──────────────────────────────────────────────────────────────
    def all(self) -> List[FindingRecord]:
        return list(self._records.values())

    def filter(self, *, state: Optional[str] = None, severity: Optional[str] = None,
               category: Optional[str] = None) -> List[FindingRecord]:
        out = list(self._records.values())
        if state:
            out = [r for r in out if r.state == state]
        if severity:
            out = [r for r in out if r.finding.get("severity") == severity]
        if category:
            out = [r for r in out if r.finding.get("category") == category]
        return out

    def stats(self) -> Dict[str, Any]:
        by_state = {s: 0 for s in LIFECYCLE}
        by_sev: Dict[str, int] = {}
        for r in self._records.values():
            by_state[r.state] = by_state.get(r.state, 0) + 1
            sev = r.finding.get("severity", "info")
            by_sev[sev] = by_sev.get(sev, 0) + 1
        open_count = sum(by_state.get(s, 0) for s in ("open", "triaged", "confirmed"))
        return {
            "total": len(self._records), "by_state": by_state,
            "by_severity": by_sev, "open": open_count,
        }
