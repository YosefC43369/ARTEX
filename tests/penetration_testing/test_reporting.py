import json

from penetration_testing.constants import (
    Confidence,
    Severity,
    ValidationStatus,
    VulnCategory,
)
from penetration_testing.models import EngagementSession, Finding
from penetration_testing.reporting.reporter import Reporter


def _session_with_findings(target_id="t1"):
    s = EngagementSession(target_id=target_id)
    s.findings = [
        Finding(target_id=target_id, category=VulnCategory.TLS_WEAKNESS,
                title="Expired cert", description="d", severity=Severity.HIGH,
                confidence=Confidence.HIGH, validation_status=ValidationStatus.CONFIRMED,
                evidence_ids=["ev1"], cvss_score=7.9, remediation="renew"),
        Finding(target_id=target_id, category=VulnCategory.SUBDOMAIN_TAKEOVER,
                title="Maybe takeover", description="d", severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM, validation_status=ValidationStatus.POTENTIAL,
                remediation="remove dangling dns"),
    ]
    return s


def test_json_report(target):
    rep = Reporter(_session_with_findings(), target)
    out = json.loads(rep.to_json())
    assert out["summary"]["overall_severity"] == "high"
    assert len(out["confirmed_findings"]) == 1
    assert len(out["potential_findings"]) == 1
    assert "limitations" in out


def test_markdown_report(target):
    md = Reporter(_session_with_findings(), target).to_markdown()
    assert "# ARTEX Assessment Report" in md
    assert "Confirmed Findings" in md
    assert "Potential Findings" in md
    assert "Expired cert" in md


def test_html_report(target):
    html = Reporter(_session_with_findings(), target).to_html()
    assert "<!doctype html>" in html.lower()
    assert "Expired cert" in html
    assert "badge confirmed" in html and "badge potential" in html


def test_build_selected_formats(target):
    out = Reporter(_session_with_findings(), target).build(["json", "html"])
    assert set(out.keys()) == {"json", "html"}
