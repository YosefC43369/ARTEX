"""
penetration_testing.intelligence.analysis
==========================================

The finding-validation pipeline: turns normalized module output into
:class:`~penetration_testing.models.Finding` objects with a disciplined
validation state, records the evidence each finding rests on, filters false
positives, and correlates related findings.

Consolidates the directive's ``vulnerability_analyzer`` / ``finding_correlator``
/ ``risk_analyzer`` / ``false_positive_filter`` / ``confidence_engine`` /
``impact_assessor`` / ``severity_calculator`` / ``cvss_calculator`` — one
pipeline with one shared Finding model.

Validation discipline
----------------------
* A finding is ``CONFIRMED`` only when the delegated module *directly observed*
  the condition (e.g. an open port, a missing response header, an expired
  certificate) **and** an evidence record is attached. ``Finding.is_consistent``
  is asserted before acceptance.
* Heuristic / AI-suggested conditions that require manual verification (e.g.
  subdomain-takeover candidates) are ``POTENTIAL`` — never silently promoted.
* The model's own reasoning, when used, is stored in ``ai_rationale`` so it is
  never confused with an observed fact.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..constants import (
    Confidence,
    EvidenceKind,
    SEVERITY_SCORE_BANDS,
    Severity,
    ValidationStatus,
    VulnCategory,
)
from ..evidence.evidence_store import EvidenceStore
from ..models import EngagementSession, Finding, Target, Task


_PORT_RISK_TO_SEVERITY = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}

# Active capability -> vulnerability category for the generic extractor.
_ACTIVE_CATEGORY = {
    "attack.web_vuln": VulnCategory.MISCONFIGURATION,
    "attack.dir_bruteforce": VulnCategory.INFO_EXPOSURE,
    "attack.bypass_403": VulnCategory.BROKEN_ACCESS_CONTROL,
    "attack.ssti": VulnCategory.SSTI,
    "attack.jwt": VulnCategory.JWT,
    "attack.db_files": VulnCategory.INFO_EXPOSURE,
    "attack.cors": VulnCategory.CORS,
    "attack.ssrf": VulnCategory.SSRF,
    "attack.xxe": VulnCategory.XXE,
    "attack.lfi": VulnCategory.PATH_TRAVERSAL,
    "attack.auth_bypass": VulnCategory.BROKEN_ACCESS_CONTROL,
    "attack.vuln_scan": VulnCategory.MISCONFIGURATION,
}

# Keys under which the active modules tend to return their finding lists.
_FINDING_LIST_KEYS = ("findings", "results", "vulnerabilities", "hits",
                      "candidates", "issues", "exposed", "matches")

_SEV_WORDS = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "low": Severity.LOW, "info": Severity.INFO, "informational": Severity.INFO,
}


class AnalysisEngine:
    def __init__(self, evidence: EvidenceStore, logger: Optional[logging.Logger] = None):
        self.evidence = evidence
        self.logger = logger or logging.getLogger(__name__)

    # ── per-task entry point ────────────────────────────────────────────────
    def analyze_task(
        self, session: EngagementSession, task: Task, target: Target,
    ) -> List[Finding]:
        dispatch = {
            "scan.ports": self._from_ports,
            "http.headers": self._from_headers,
            "tls.inspect": self._from_tls,
            "recon.takeover": self._from_takeover,
            "recon.subdomains": self._from_subdomains,
        }
        handler = dispatch.get(task.capability)
        if handler is None and task.capability in _ACTIVE_CATEGORY:
            handler = self._from_active
        if handler is None:
            return []
        try:
            findings = handler(task, target)
        except Exception as exc:  # never let analysis crash the engagement
            self.logger.warning("Analysis of %s failed: %s", task.capability, exc)
            return []
        # enforce the CONFIRMED-needs-evidence invariant
        return [f for f in findings if f.is_consistent()]

    # ── severity / scoring helpers ──────────────────────────────────────────
    @staticmethod
    def _cvss_for(severity: Severity) -> float:
        low, high = SEVERITY_SCORE_BANDS[severity]
        return round((low + high) / 2, 1)

    def _finish(self, f: Finding) -> Finding:
        f.cvss_score = self._cvss_for(f.severity)
        return f

    def _record(self, target_id, task_id, summary, data) -> str:
        ev = self.evidence.record(
            target_id=target_id, task_id=task_id,
            kind=EvidenceKind.OBSERVATION, summary=summary, data=data,
        )
        return ev.evidence_id if ev else ""

    # ── extractors ──────────────────────────────────────────────────────────
    def _from_ports(self, task: Task, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        for host in task.result.get("port_scan", []) or []:
            hostname = host.get("target", target.domain)
            for port in host.get("ports", []) or []:
                risk = (port.get("risk") or {})
                level = str(risk.get("level", "info")).lower()
                sev = _PORT_RISK_TO_SEVERITY.get(level, Severity.INFO)
                if sev.rank < Severity.MEDIUM.rank:
                    continue  # only surface medium+ exposed services as findings
                ev_id = self._record(
                    target.identifier, task.task_id,
                    f"Open port {port.get('port')} on {hostname}",
                    {"host": hostname, "port": port.get("port"),
                     "service": port.get("service"), "risk": risk},
                )
                findings.append(self._finish(Finding(
                    target_id=target.identifier,
                    category=VulnCategory.MISCONFIGURATION,
                    title=f"Exposed service: {port.get('service','?')} on port {port.get('port')}",
                    description=(f"Port {port.get('port')}/{port.get('protocol','tcp')} "
                                 f"({port.get('service','?')}) is reachable on {hostname}."),
                    endpoint=f"{hostname}:{port.get('port')}",
                    technical_detail=str(risk.get("vulnerabilities", "")),
                    evidence_ids=[ev_id] if ev_id else [],
                    severity=sev,
                    confidence=Confidence.HIGH,
                    validation_status=ValidationStatus.CONFIRMED,
                    demonstrated_impact="Service confirmed reachable.",
                    potential_impact="Expanded attack surface; verify service hardening.",
                    remediation="Restrict exposure via firewall/segmentation; patch the service.",
                )))
        return findings

    def _from_headers(self, task: Task, target: Target) -> List[Finding]:
        analysis = task.result.get("header_analysis") or {}
        missing = (analysis.get("missing_headers") or analysis.get("missing")
                   or analysis.get("missing_security_headers") or [])
        if not isinstance(missing, list) or not missing:
            return []
        ev_id = self._record(
            target.identifier, task.task_id,
            "Missing security headers observed",
            {"missing_headers": missing[:30]},
        )
        return [self._finish(Finding(
            target_id=target.identifier,
            category=VulnCategory.MISSING_HEADERS,
            title=f"Missing security headers ({len(missing)})",
            description=("The response omits recommended security headers: "
                         + ", ".join(str(m) for m in missing[:12])),
            endpoint=target.url,
            evidence_ids=[ev_id] if ev_id else [],
            severity=Severity.MEDIUM if len(missing) >= 3 else Severity.LOW,
            confidence=Confidence.HIGH,
            validation_status=ValidationStatus.CONFIRMED,  # directly observed absence
            demonstrated_impact="Headers confirmed absent in server response.",
            potential_impact="Weakened defense-in-depth against XSS/clickjacking/MITM.",
            remediation="Add CSP, HSTS, X-Content-Type-Options, X-Frame-Options, etc.",
        ))]

    def _from_tls(self, task: Task, target: Target) -> List[Finding]:
        tls = task.result.get("tls") or {}
        findings: List[Finding] = []

        # Expired / invalid certificate (definitive observation when present).
        if tls.get("expired") is True or tls.get("is_expired") is True:
            ev_id = self._record(target.identifier, task.task_id,
                                 "Expired TLS certificate", {"tls": self._tls_summary(tls)})
            findings.append(self._finish(Finding(
                target_id=target.identifier, category=VulnCategory.TLS_WEAKNESS,
                title="Expired TLS certificate", description="The server presents an expired certificate.",
                endpoint=target.domain, evidence_ids=[ev_id] if ev_id else [],
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                validation_status=ValidationStatus.CONFIRMED,
                demonstrated_impact="Certificate validity window has passed.",
                potential_impact="Clients may bypass warnings; MITM risk.",
                remediation="Renew and automate certificate rotation.",
            )))

        # Weak/deprecated protocols, if the module enumerates supported ones.
        protos = tls.get("protocols") or tls.get("supported_protocols") or {}
        weak = []
        if isinstance(protos, dict):
            weak = [p for p, on in protos.items()
                    if on and str(p).upper().replace(" ", "") in
                    ("SSLV2", "SSLV3", "TLS1.0", "TLSV1.0", "TLS1.1", "TLSV1.1")]
        if weak:
            ev_id = self._record(target.identifier, task.task_id,
                                 "Deprecated TLS protocols enabled", {"weak_protocols": weak})
            findings.append(self._finish(Finding(
                target_id=target.identifier, category=VulnCategory.TLS_WEAKNESS,
                title="Deprecated TLS/SSL protocols enabled",
                description="Server negotiates deprecated protocols: " + ", ".join(map(str, weak)),
                endpoint=target.domain, evidence_ids=[ev_id] if ev_id else [],
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                validation_status=ValidationStatus.CONFIRMED,
                demonstrated_impact="Weak protocols confirmed enabled.",
                potential_impact="Downgrade attacks; weakened transport security.",
                remediation="Disable SSLv2/3 and TLS 1.0/1.1; require TLS 1.2+.",
            )))
        return findings

    def _from_takeover(self, task: Task, target: Target) -> List[Finding]:
        ta = task.result.get("takeover_analysis") or {}
        findings: List[Finding] = []
        for item in (ta.get("vulnerable") or []):
            sub = item.get("subdomain") if isinstance(item, dict) else str(item)
            ev_id = self._record(target.identifier, task.task_id,
                                 f"Subdomain takeover candidate: {sub}",
                                 {"item": item})
            findings.append(self._finish(Finding(
                target_id=target.identifier, category=VulnCategory.SUBDOMAIN_TAKEOVER,
                title=f"Possible subdomain takeover: {sub}",
                description=("A dangling/misconfigured delegation suggests a possible "
                             "takeover. Requires manual verification before exploitation."),
                endpoint=str(sub),
                evidence_ids=[ev_id] if ev_id else [],
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                # Heuristic — NOT confirmed without manual claim of the resource.
                validation_status=ValidationStatus.POTENTIAL,
                potential_impact="Attacker could serve content on a trusted subdomain.",
                remediation="Remove dangling DNS records or reclaim the backing resource.",
                ai_rationale=str(item.get("service")) if isinstance(item, dict) else "",
            )))
        return findings

    def _from_subdomains(self, task: Task, target: Target) -> List[Finding]:
        subs = task.result.get("subdomains") or []
        if not subs:
            return []
        ev_id = self._record(target.identifier, task.task_id,
                             f"{len(subs)} subdomains enumerated",
                             {"count": len(subs)})
        return [self._finish(Finding(
            target_id=target.identifier, category=VulnCategory.INFO_EXPOSURE,
            title=f"Attack surface: {len(subs)} subdomains discovered",
            description="Enumerated subdomains expand the reviewable attack surface.",
            endpoint=target.domain, evidence_ids=[ev_id] if ev_id else [],
            severity=Severity.INFO, confidence=Confidence.HIGH,
            validation_status=ValidationStatus.CONFIRMED,
            demonstrated_impact="Subdomains confirmed resolvable/enumerable.",
            remediation="Review each subdomain for exposure and decommission unused hosts.",
        ))]

    @staticmethod
    def _tls_summary(tls: Dict[str, Any]) -> Dict[str, Any]:
        return {k: tls.get(k) for k in ("subject", "issuer", "not_after", "expired")
                if k in tls}

    # ── generic extractor for active/offensive module output ─────────────────
    def _from_active(self, task: Task, target: Target) -> List[Finding]:
        """Surface findings from an active offensive module.

        Active-test results are classified ``POTENTIAL`` (not CONFIRMED): a
        red-team operator verifies them before claiming exploitability. The raw
        item is recorded as evidence so the finding is traceable.
        """
        cap = task.capability
        category = _ACTIVE_CATEGORY.get(cap, VulnCategory.MISCONFIGURATION)
        data = next(iter(task.result.values()), {}) if task.result else {}
        items = self._extract_items(data)
        findings: List[Finding] = []
        for item in items[:25]:
            sev = self._item_severity(item)
            if sev.rank < Severity.LOW.rank:
                continue
            ev_id = self._record(
                target.identifier, task.task_id, f"{cap} result",
                {"item": item if isinstance(item, dict) else str(item)})
            findings.append(self._finish(Finding(
                target_id=target.identifier,
                category=category,
                title=self._item_title(cap, item, category),
                description=self._item_desc(item),
                endpoint=self._item_endpoint(item, target),
                technical_detail=str(item)[:400] if not isinstance(item, dict) else "",
                evidence_ids=[ev_id] if ev_id else [],
                severity=sev,
                confidence=Confidence.MEDIUM,
                validation_status=ValidationStatus.POTENTIAL,
                potential_impact="Active-test indicator — verify manually before "
                                 "asserting exploitability.",
                remediation=(item.get("remediation", "") if isinstance(item, dict) else ""),
            )))
        return findings

    @staticmethod
    def _extract_items(data: Any) -> List[Any]:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in _FINDING_LIST_KEYS:
                val = data.get(key)
                if isinstance(val, list) and val:
                    return val
            # nested: some modules wrap under a single sub-dict
            for val in data.values():
                if isinstance(val, dict):
                    for key in _FINDING_LIST_KEYS:
                        inner = val.get(key)
                        if isinstance(inner, list) and inner:
                            return inner
        return []

    @staticmethod
    def _item_severity(item: Any) -> Severity:
        if isinstance(item, dict):
            raw = str(item.get("severity") or item.get("risk") or
                      item.get("level") or "medium").lower()
            return _SEV_WORDS.get(raw, Severity.MEDIUM)
        return Severity.MEDIUM

    @staticmethod
    def _item_title(cap: str, item: Any, category: VulnCategory) -> str:
        label = cap.split(".", 1)[-1].replace("_", " ")
        if isinstance(item, dict):
            t = item.get("title") or item.get("name") or item.get("type") \
                or item.get("variant")
            if t:
                return f"{label}: {t}"
        return f"{label} indicator ({category.value})"

    @staticmethod
    def _item_desc(item: Any) -> str:
        if isinstance(item, dict):
            return str(item.get("description") or item.get("detail")
                       or item.get("evidence") or item.get("summary") or "")[:400]
        return str(item)[:400]

    @staticmethod
    def _item_endpoint(item: Any, target: Target) -> str:
        if isinstance(item, dict):
            return str(item.get("url") or item.get("endpoint")
                       or item.get("path") or item.get("parameter") or target.url)
        return target.url

    # ── session finalization: dedupe, FP filter, correlate ──────────────────
    def finalize(self, session: EngagementSession) -> Dict[str, Any]:
        seen = set()
        deduped: List[Finding] = []
        for f in session.findings:
            key = (str(f.category), f.endpoint, f.title)
            if key in seen:
                continue
            if not f.is_consistent():      # false-positive safety net
                f.validation_status = ValidationStatus.INCONCLUSIVE
            seen.add(key)
            deduped.append(f)
        session.findings = sorted(
            deduped, key=lambda x: (x.severity.rank, x.cvss_score), reverse=True)

        correlations = self._correlate(session.findings)
        return {
            "total": len(session.findings),
            "confirmed": sum(1 for f in session.findings
                             if f.validation_status == ValidationStatus.CONFIRMED),
            "potential": sum(1 for f in session.findings
                             if f.validation_status == ValidationStatus.POTENTIAL),
            "correlations": correlations,
        }

    @staticmethod
    def _correlate(findings: List[Finding]) -> List[Dict[str, Any]]:
        """Surface simple, defensible relationships between findings."""
        links: List[Dict[str, Any]] = []
        takeovers = [f for f in findings if f.category == VulnCategory.SUBDOMAIN_TAKEOVER]
        missing_hdrs = [f for f in findings if f.category == VulnCategory.MISSING_HEADERS]
        if takeovers and missing_hdrs:
            links.append({
                "relationship": "takeover_amplified_by_weak_headers",
                "finding_ids": [f.finding_id for f in takeovers + missing_hdrs],
                "note": "Takeover candidates combined with weak headers increase "
                        "phishing/content-injection impact on trusted subdomains.",
            })
        return links
