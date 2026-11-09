"""
penetration_testing.intelligence.validation
============================================

Finding validation + false-positive reduction (serves "accurate reports").

For each finding this engine:
1. Gathers the evidence text backing it (from the evidence store + the finding's
   own detail fields).
2. Corroborates against the detection-signature library: a strong indicator
   match on real evidence can PROMOTE a POTENTIAL finding to CONFIRMED; absence
   of any corroboration keeps it POTENTIAL or flags a likely false positive.
3. Stamps the finding with its CWE and MITRE ATT&CK ids for standards-aligned
   reporting.
4. Applies conservative false-positive heuristics and drops clear FPs.

The guiding rule is unchanged: CONFIRMED requires evidence. This engine only
ever promotes when there is corroborating evidence, and demotes/drops when a
finding has nothing to stand on — which is exactly what makes a report accurate.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from ..constants import Confidence, Severity, ValidationStatus
from ..evidence.evidence_store import EvidenceStore
from ..models import Finding
from .signatures import SignatureLibrary


# Categories that are active/injection classes — for these, a finding with no
# corroborating evidence is treated as a likely false positive.
_INJECTION_CATEGORIES = {
    "sql_injection", "cross_site_scripting", "ssrf",
    "server_side_template_injection", "xml_external_entity", "path_traversal",
    "prototype_pollution", "mass_assignment",
}


class FindingValidator:
    def __init__(self, evidence: EvidenceStore,
                 signatures: Optional[SignatureLibrary] = None,
                 logger: Optional[logging.Logger] = None):
        self.evidence = evidence
        self.signatures = signatures or SignatureLibrary()
        self.logger = logger or logging.getLogger(__name__)

    # ── evidence gathering ───────────────────────────────────────────────────
    def _evidence_text(self, finding: Finding) -> str:
        parts = [finding.description, finding.technical_detail]
        for ev_id in finding.evidence_ids:
            ev = self.evidence.get(ev_id)
            if ev:
                parts.append(ev.summary or "")
                parts.append(ev.response_excerpt or "")
                parts.append(repr(ev.data))
        return "\n".join(p for p in parts if p)

    # ── single-finding validation ────────────────────────────────────────────
    def validate(self, finding: Finding) -> Finding:
        category = finding.category.value
        # 1. standards mapping (always stamp, even if already set elsewhere)
        mapping = self.signatures.mapping(category)
        if not finding.cwe:
            finding.cwe = mapping["cwe"]
        if not finding.mitre:
            finding.mitre = list(mapping["mitre"])
        if not finding.references and mapping["references"]:
            finding.references = list(mapping["references"])

        # 2. corroborate against evidence
        text = self._evidence_text(finding)
        matched = self.signatures.corroborate(category, text)

        # 3. decide status
        if finding.validation_status == ValidationStatus.CONFIRMED:
            # already confirmed by a direct observation (e.g. missing header) —
            # keep it, but require it still has evidence (invariant).
            if not finding.evidence_ids:
                finding.validation_status = ValidationStatus.INCONCLUSIVE
            return finding

        if finding.validation_status == ValidationStatus.POTENTIAL:
            if matched and finding.evidence_ids:
                # strong corroboration on real evidence -> promote
                finding.validation_status = ValidationStatus.CONFIRMED
                finding.confidence = Confidence.HIGH
                finding.demonstrated_impact = (
                    finding.demonstrated_impact
                    or f"Corroborated by {len(matched)} detection signature(s).")
                return finding
            fp, reason = self._is_false_positive(finding, text, matched)
            if fp:
                finding.validation_status = ValidationStatus.FALSE_POSITIVE
                finding.fp_reason = reason
                finding.confidence = Confidence.LOW
            return finding

        return finding

    def _is_false_positive(self, finding: Finding, text: str,
                           matched: List[str]) -> Tuple[bool, str]:
        category = finding.category.value
        # Injection-class finding with no corroborating evidence and no concrete
        # endpoint/detail is almost certainly noise.
        if category in _INJECTION_CATEGORIES and not matched:
            if not finding.evidence_ids:
                return True, "injection-class finding with no supporting evidence"
            if not finding.technical_detail and not finding.description.strip():
                return True, "no distinguishing evidence content"
        # Info-severity finding with nothing attached.
        if (finding.severity == Severity.INFO and not finding.evidence_ids
                and not finding.endpoint):
            return True, "informational with no evidence or endpoint"
        return False, ""

    # ── batch validation ─────────────────────────────────────────────────────
    def validate_findings(self, findings: List[Finding]) -> Tuple[List[Finding], Dict[str, Any]]:
        """Validate all findings; return (kept, stats). False positives are
        removed from the kept list but counted."""
        kept: List[Finding] = []
        fp = promoted = 0
        for f in findings:
            before = f.validation_status
            self.validate(f)
            if f.validation_status == ValidationStatus.FALSE_POSITIVE:
                fp += 1
                continue
            if (before == ValidationStatus.POTENTIAL
                    and f.validation_status == ValidationStatus.CONFIRMED):
                promoted += 1
            kept.append(f)
        stats = {
            "input": len(findings), "kept": len(kept),
            "false_positives_removed": fp, "promoted_to_confirmed": promoted,
        }
        return kept, stats
