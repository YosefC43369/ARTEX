"""
penetration_testing.reporting.reporter
=======================================

Builds assessment reports in JSON, Markdown and HTML from an
:class:`~penetration_testing.models.EngagementSession`.

Consolidates the directive's ``reporter`` / ``report_builder`` /
``executive_summary`` / ``technical_report`` / ``remediation_advisor`` /
``report_exporter`` / ``report_templates`` concerns.

Integrity of claims
-------------------
The reporter never promotes a finding's status. It renders findings exactly as
the analysis layer validated them and keeps a hard visual separation between
**confirmed** (evidence-backed, observed) and **potential** (requires manual
verification) results. It also states assessment limitations explicitly.
"""

from __future__ import annotations

import html
import json
import time
from typing import Any, Dict, List

from ..constants import Severity, ValidationStatus
from ..models import EngagementSession, Finding, Target


class Reporter:
    def __init__(self, session: EngagementSession, target: Target):
        self.session = session
        self.target = target

    # ── public API ───────────────────────────────────────────────────────────
    def build(self, formats: List[str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for fmt in formats:
            fmt = fmt.lower()
            if fmt == "json":
                out["json"] = self.to_json()
            elif fmt in ("markdown", "md"):
                out["markdown"] = self.to_markdown()
            elif fmt == "html":
                out["html"] = self.to_html()
        return out

    # ── shared summary ───────────────────────────────────────────────────────
    def _severity_breakdown(self) -> Dict[str, int]:
        buckets = {s.value: 0 for s in Severity}
        for f in self.session.findings:
            buckets[f.severity.value] += 1
        return buckets

    def _confirmed(self) -> List[Finding]:
        return [f for f in self.session.findings
                if f.validation_status == ValidationStatus.CONFIRMED]

    def _potential(self) -> List[Finding]:
        return [f for f in self.session.findings
                if f.validation_status == ValidationStatus.POTENTIAL]

    def _overall_severity(self) -> str:
        if not self.session.findings:
            return "informational"
        top = max(self.session.findings, key=lambda f: f.severity.rank)
        return top.severity.value

    # ── JSON ─────────────────────────────────────────────────────────────────
    def to_json(self) -> str:
        payload = {
            "report_type": "ARTEX Autonomous Assessment",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "scope": {
                "target_id": self.target.identifier,
                "domain": self.target.domain,
                "url": self.target.url,
                "authorized_scope": self.target.allowed_domains,
            },
            "summary": {
                "overall_severity": self._overall_severity(),
                "severity_breakdown": self._severity_breakdown(),
                "counts": self.session.counts(),
            },
            "methodology": self._methodology(),
            "confirmed_findings": [f.to_dict() for f in self._confirmed()],
            "potential_findings": [f.to_dict() for f in self._potential()],
            "evidence_integrity": self.session.metadata.get("evidence_chain", {}),
            "limitations": self._limitations(),
        }
        return json.dumps(payload, indent=2, default=str)

    # ── Markdown ─────────────────────────────────────────────────────────────
    def to_markdown(self) -> str:
        b = self._severity_breakdown()
        lines = [
            f"# ARTEX Assessment Report — {self.target.domain}",
            "",
            f"*Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}*",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Overall severity:** {self._overall_severity().upper()}",
            f"- **Confirmed findings:** {len(self._confirmed())}",
            f"- **Potential findings (need manual verification):** {len(self._potential())}",
            f"- **Severity breakdown:** "
            f"Critical {b['critical']} · High {b['high']} · Medium {b['medium']} · "
            f"Low {b['low']} · Info {b['info']}",
            "",
            "## 2. Scope",
            "",
            f"- Target: `{self.target.identifier}` — {self.target.url}",
            f"- Authorized domains: {', '.join(self.target.allowed_domains)}",
            "",
            "## 3. Methodology",
            "",
        ]
        lines += [f"- {m}" for m in self._methodology()]
        lines += ["", "## 4. Confirmed Findings", ""]
        if self._confirmed():
            for f in self._confirmed():
                lines += self._md_finding(f)
        else:
            lines.append("_No confirmed findings._")
        lines += ["", "## 5. Potential Findings (require manual verification)", ""]
        if self._potential():
            for f in self._potential():
                lines += self._md_finding(f)
        else:
            lines.append("_No potential findings._")
        lines += ["", "## 6. Assessment Limitations", ""]
        lines += [f"- {m}" for m in self._limitations()]
        return "\n".join(lines)

    def _md_finding(self, f: Finding) -> List[str]:
        return [
            f"### [{f.severity.value.upper()}] {f.title}",
            "",
            f"- **Category:** {f.category.value}"
            + (f" · **{f.cwe}**" if f.cwe else "")
            + (f" · ATT&CK {', '.join(f.mitre)}" if f.mitre else ""),
            f"- **Status:** {f.validation_status.value} "
            f"(confidence: {f.confidence.value})",
            f"- **Endpoint:** `{f.endpoint}`",
            f"- **CVSS (approx):** {f.cvss_score}",
            f"- **Description:** {f.description}",
            (f"- **Technical detail:** {f.technical_detail}" if f.technical_detail else ""),
            (f"- **Demonstrated impact:** {f.demonstrated_impact}"
             if f.demonstrated_impact else ""),
            (f"- **Potential impact:** {f.potential_impact}" if f.potential_impact else ""),
            f"- **Remediation:** {f.remediation}",
            f"- **Evidence:** {', '.join(f.evidence_ids) or 'n/a'}",
            "",
        ]

    # ── HTML ─────────────────────────────────────────────────────────────────
    def to_html(self) -> str:
        def esc(x: Any) -> str:
            return html.escape(str(x))

        rows = []
        for f in self.session.findings:
            badge = "confirmed" if f.validation_status == ValidationStatus.CONFIRMED else "potential"
            rows.append(
                f"<tr class='sev-{f.severity.value}'>"
                f"<td>{esc(f.severity.value.upper())}</td>"
                f"<td>{esc(f.title)}</td>"
                f"<td>{esc(f.category.value)}</td>"
                f"<td><span class='badge {badge}'>{esc(f.validation_status.value)}</span></td>"
                f"<td><code>{esc(f.endpoint)}</code></td>"
                f"<td>{esc(f.remediation)}</td></tr>"
            )
        b = self._severity_breakdown()
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARTEX Assessment — {esc(self.target.domain)}</title>
<style>
 body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}}
 .wrap{{max-width:1000px;margin:0 auto;padding:24px 16px}}
 h1{{font-size:1.5rem}} .muted{{color:#94a3b8}}
 table{{width:100%;border-collapse:collapse;margin-top:16px;font-size:.88rem}}
 th,td{{text-align:left;padding:.55rem .6rem;border-bottom:1px solid #1e293b;vertical-align:top}}
 th{{color:#93c5fd;text-transform:uppercase;font-size:.72rem;letter-spacing:.04em}}
 .badge{{padding:.1rem .5rem;border-radius:12px;font-size:.72rem;font-weight:700}}
 .badge.confirmed{{background:#065f46;color:#d1fae5}} .badge.potential{{background:#78350f;color:#fed7aa}}
 .sev-critical td:first-child{{color:#f87171;font-weight:700}}
 .sev-high td:first-child{{color:#fb923c;font-weight:700}}
 .sev-medium td:first-child{{color:#60a5fa;font-weight:700}}
 .sev-low td:first-child{{color:#34d399}} .sev-info td:first-child{{color:#94a3b8}}
 .cards{{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}}
 .card{{background:#1e293b;border-radius:10px;padding:.7rem 1rem;font-weight:700}}
</style></head><body><div class="wrap">
<h1>ARTEX Autonomous Assessment — {esc(self.target.domain)}</h1>
<p class="muted">Generated {time.strftime('%Y-%m-%d %H:%M:%S')} · Overall: <b>{esc(self._overall_severity().upper())}</b></p>
<div class="cards">
 <div class="card">Confirmed: {len(self._confirmed())}</div>
 <div class="card">Potential: {len(self._potential())}</div>
 <div class="card">Critical {b['critical']}</div>
 <div class="card">High {b['high']}</div>
 <div class="card">Medium {b['medium']}</div>
</div>
<table><thead><tr><th>Sev</th><th>Finding</th><th>Category</th><th>Status</th><th>Endpoint</th><th>Remediation</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=6 class=muted>No findings.</td></tr>'}</tbody></table>
<p class="muted" style="margin-top:20px;font-size:.8rem">Confirmed findings are evidence-backed observations.
Potential findings require manual verification and are not asserted as exploitable.</p>
</div></body></html>"""

    # ── shared text blocks ───────────────────────────────────────────────────
    def _methodology(self) -> List[str]:
        caps = sorted({t.capability for t in self.session.tasks})
        return [
            "Authorized, non-destructive assessment bounded by config.xml scope.",
            "Capabilities exercised: " + (", ".join(caps) if caps else "none"),
            "Findings validated against collected evidence before classification.",
        ]

    def _limitations(self) -> List[str]:
        return [
            "Assessment is limited to the authorized scope in config.xml.",
            "Potential findings are heuristic and require manual verification.",
            "No destructive, exploitation, or data-extraction testing was performed.",
            "Delegated modules enforce scope at the target boundary, not per-packet.",
        ]
