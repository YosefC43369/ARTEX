"""
penetration_testing.intelligence.modern_detectors
==================================================

Detection for modern vulnerability classes that the base scanners don't
classify on their own (serves "add modern techniques for accurate reports").

These are **detection analyzers**, not new network attackers: they inspect the
data the active modules already collected for the current engagement and flag
indicators of modern issues, using the shared signature library for
corroboration and CWE/MITRE mapping. Everything they emit is ``POTENTIAL``
(indicator-level) — a red-team operator verifies before asserting exploitability.

Classes covered:
* GraphQL introspection / exposure
* Prototype pollution indicators
* Mass assignment (writable privileged properties)
* OAuth / SAML misconfiguration
* HTTP request smuggling indicators
* IDOR / BOLA candidate parameters
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..constants import Confidence, EvidenceKind, Severity, ValidationStatus, VulnCategory
from ..evidence.evidence_store import EvidenceStore
from ..models import EngagementSession, Finding, Target
from .signatures import SignatureLibrary


# (category key, VulnCategory, title, default severity)
_MODERN = [
    ("graphql_exposure", VulnCategory.GRAPHQL,
     "GraphQL introspection / exposure", Severity.MEDIUM),
    ("prototype_pollution", VulnCategory.PROTOTYPE_POLLUTION,
     "Prototype pollution indicator", Severity.HIGH),
    ("mass_assignment", VulnCategory.MASS_ASSIGNMENT,
     "Mass assignment of privileged property", Severity.HIGH),
    ("oauth_saml_misconfig", VulnCategory.OAUTH_SAML,
     "OAuth / SAML misconfiguration indicator", Severity.MEDIUM),
    ("http_request_smuggling", VulnCategory.REQUEST_SMUGGLING,
     "HTTP request smuggling indicator", Severity.HIGH),
]


class ModernDetectors:
    def __init__(self, evidence: EvidenceStore,
                 signatures: Optional[SignatureLibrary] = None,
                 logger: Optional[logging.Logger] = None):
        self.evidence = evidence
        self.signatures = signatures or SignatureLibrary()
        self.logger = logger or logging.getLogger(__name__)

    def run(self, session: EngagementSession, target: Target) -> List[Finding]:
        blob = self._collect_text(session)
        findings: List[Finding] = []

        for key, category, title, severity in _MODERN:
            matched = self.signatures.corroborate(key, blob)
            if not matched:
                continue
            mapping = self.signatures.mapping(key)
            ev_id = self._record(target.identifier, key, matched)
            findings.append(Finding(
                target_id=target.identifier, category=category, title=title,
                description=f"Indicators of {title.lower()} were observed in "
                            f"collected responses ({len(matched)} signature match(es)).",
                endpoint=target.url,
                technical_detail="matched: " + "; ".join(matched[:4]),
                evidence_ids=[ev_id] if ev_id else [],
                severity=severity, confidence=Confidence.MEDIUM,
                validation_status=ValidationStatus.POTENTIAL,
                potential_impact="Modern-class indicator — verify manually before "
                                 "asserting exploitability.",
                cwe=mapping["cwe"], mitre=list(mapping["mitre"]),
                references=list(mapping["references"]),
            ))

        findings.extend(self._idor_candidates(session, target))
        return findings

    # ── IDOR / BOLA candidate detection (structured, not signature-based) ─────
    def _idor_candidates(self, session: EngagementSession, target: Target) -> List[Finding]:
        """Flag API endpoints exposing object identifiers in parameters — the
        classic BOLA/IDOR surface — as candidates for manual authorization
        testing."""
        import re
        candidates = set()
        id_param = re.compile(r"[?&/](id|user_?id|account|order|uuid|doc|file)=?\d", re.I)
        for task in session.tasks:
            for val in self._iter_strings(task.result):
                if id_param.search(val):
                    candidates.add(val[:160])
        if not candidates:
            return []
        mapping = self.signatures.mapping("idor_bola")
        ev_id = self._record(target.identifier, "idor_bola", list(candidates)[:10])
        return [Finding(
            target_id=target.identifier, category=VulnCategory.IDOR,
            title=f"IDOR/BOLA candidate endpoints ({len(candidates)})",
            description="Endpoints expose object identifiers in parameters; test "
                        "each for broken object-level authorization (access another "
                        "user's object).",
            endpoint=target.url,
            technical_detail="; ".join(list(candidates)[:5]),
            evidence_ids=[ev_id] if ev_id else [],
            severity=Severity.MEDIUM, confidence=Confidence.LOW,
            validation_status=ValidationStatus.POTENTIAL,
            potential_impact="Possible cross-tenant/user data access if authz is "
                             "not enforced per object.",
            remediation="Enforce per-object authorization server-side for every "
                        "identifier-bearing endpoint.",
            cwe=mapping["cwe"], mitre=list(mapping["mitre"]),
            references=list(mapping["references"]),
        )]

    # ── helpers ──────────────────────────────────────────────────────────────
    def _collect_text(self, session: EngagementSession) -> str:
        chunks: List[str] = []
        for task in session.tasks:
            chunks.extend(self._iter_strings(task.result))
        return "\n".join(chunks)[:200000]   # bound the scan size

    @staticmethod
    def _iter_strings(obj: Any) -> List[str]:
        out: List[str] = []
        stack = [obj]
        while stack:
            cur = stack.pop()
            if isinstance(cur, str):
                out.append(cur)
            elif isinstance(cur, dict):
                for k, v in cur.items():
                    out.append(str(k))
                    stack.append(v)
            elif isinstance(cur, (list, tuple)):
                stack.extend(cur)
            elif cur is not None:
                out.append(str(cur))
        return out

    def _record(self, target_id: str, key: str, matched: List[str]) -> str:
        ev = self.evidence.record(
            target_id=target_id, task_id="modern-detect",
            kind=EvidenceKind.OBSERVATION,
            summary=f"modern-class indicator: {key}",
            data={"category": key, "matched": matched[:10]})
        return ev.evidence_id if ev else ""
