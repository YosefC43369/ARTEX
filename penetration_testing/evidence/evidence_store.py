"""
penetration_testing.evidence.evidence_store
============================================

Structured evidence collection with a per-session integrity chain.

Consolidates the directive's ``evidence_collector`` / ``evidence_validator`` /
``evidence_store`` / ``request_response_recorder`` / ``integrity_checker`` into
one cohesive component — they are facets of a single concern (record evidence,
keep it verifiable, persist it) and are far easier to keep consistent together.

Design points
-------------
* Each :class:`~penetration_testing.models.Evidence` self-hashes on creation.
* The store additionally maintains a **hash chain**: each record's chain digest
  folds in the previous record's digest, so tampering with any earlier record
  invalidates every later link. :meth:`verify_chain` detects this.
* Evidence is kept separate from execution logs and is always traceable to the
  task that produced it (``task_id``).
* Response bodies are **truncated and redacted** before storage to avoid
  retaining bulk sensitive/production data or secrets.
* Optional JSON persistence to a configured directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from typing import Any, Dict, List, Optional

from ..exceptions import StorageError
from ..models import Evidence
from ..constants import EvidenceKind


# Patterns redacted from any stored response excerpt / header set.
_REDACTIONS = [
    (re.compile(r"(?i)(authorization|cookie|set-cookie|x-api-key|api[-_]?key)"
                r"(\s*[:=]\s*)(\S+)"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)(password|passwd|secret|token)(\"?\s*[:=]\s*\"?)([^\"&\s]+)"),
     r"\1\2[REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
     "[REDACTED_JWT]"),
]

_MAX_EXCERPT = 2048


def redact(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    out = text[:_MAX_EXCERPT]
    for pattern, repl in _REDACTIONS:
        out = pattern.sub(repl, out)
    return out


class EvidenceStore:
    def __init__(
        self,
        enabled: bool = True,
        persist_dir: Optional[str] = None,
    ):
        self.enabled = enabled
        self.persist_dir = persist_dir
        self._records: List[Evidence] = []
        self._by_id: Dict[str, Evidence] = {}
        # Chain digests are kept here, NOT inside Evidence.data — the record's
        # own sha256 covers data, so mutating data would break Evidence.verify().
        self._chain: Dict[str, str] = {}
        self._chain_tail = "0" * 64
        self._lock = threading.Lock()
        if self.persist_dir:
            try:
                os.makedirs(self.persist_dir, exist_ok=True)
            except OSError as exc:
                raise StorageError("Cannot create evidence directory.",
                                   detail=str(exc)) from exc

    def _chain_digest(self, ev: Evidence) -> str:
        h = hashlib.sha256()
        h.update(self._chain_tail.encode())
        h.update(ev.sha256.encode())
        return h.hexdigest()

    def record(
        self,
        *,
        target_id: str,
        task_id: str,
        kind: EvidenceKind,
        summary: str,
        request: Optional[Dict[str, Any]] = None,
        response_excerpt: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Optional[Evidence]:
        """Create, chain and store one evidence record. Returns it (or ``None``
        when evidence collection is disabled)."""
        if not self.enabled:
            return None

        ev = Evidence(
            target_id=target_id,
            task_id=task_id,
            kind=kind,
            summary=summary[:500],
            request=self._sanitize_request(request),
            response_excerpt=redact(response_excerpt),
            data=data or {},
        )
        with self._lock:
            digest = self._chain_digest(ev)
            self._chain[ev.evidence_id] = digest
            self._chain_tail = digest
            self._records.append(ev)
            self._by_id[ev.evidence_id] = ev
        self._persist(ev)
        return ev

    @staticmethod
    def _sanitize_request(request: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not request:
            return request
        safe = dict(request)
        headers = safe.get("headers")
        if isinstance(headers, dict):
            safe["headers"] = {
                k: ("[REDACTED]" if k.lower() in
                    ("authorization", "cookie", "x-api-key") else v)
                for k, v in headers.items()
            }
        if "body" in safe and isinstance(safe["body"], str):
            safe["body"] = redact(safe["body"])
        return safe

    def _persist(self, ev: Evidence) -> None:
        if not self.persist_dir:
            return
        try:
            path = os.path.join(self.persist_dir, f"{ev.evidence_id}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(ev.to_dict(), fh, indent=2, default=str)
        except OSError as exc:  # non-fatal: evidence still lives in memory
            raise StorageError("Failed to persist evidence record.",
                               detail=str(exc)) from exc

    def get(self, evidence_id: str) -> Optional[Evidence]:
        return self._by_id.get(evidence_id)

    def for_task(self, task_id: str) -> List[Evidence]:
        return [e for e in self._records if e.task_id == task_id]

    def all(self) -> List[Evidence]:
        return list(self._records)

    def verify_chain(self) -> Dict[str, Any]:
        """Recompute the integrity chain. Reports the first broken link, if any."""
        tail = "0" * 64
        for idx, ev in enumerate(self._records):
            if not ev.verify():
                return {"valid": False, "broken_at": idx, "reason": "record hash mismatch"}
            expect = hashlib.sha256((tail + ev.sha256).encode()).hexdigest()
            if self._chain.get(ev.evidence_id) != expect:
                return {"valid": False, "broken_at": idx, "reason": "chain digest mismatch"}
            tail = expect
        return {"valid": True, "records": len(self._records)}

    def stats(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = {}
        for ev in self._records:
            by_kind[str(ev.kind)] = by_kind.get(str(ev.kind), 0) + 1
        return {"total": len(self._records), "by_kind": by_kind}
