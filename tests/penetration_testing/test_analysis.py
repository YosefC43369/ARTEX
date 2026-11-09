from penetration_testing.constants import (
    Phase,
    Severity,
    ValidationStatus,
    VulnCategory,
)
from penetration_testing.evidence.evidence_store import EvidenceStore
from penetration_testing.intelligence.analysis import AnalysisEngine
from penetration_testing.models import EngagementSession, Task


def _task(cap, result):
    t = Task(phase=Phase.ANALYSIS, capability=cap)
    t.result = result
    return t


def test_ports_finding_confirmed(evidence, target):
    eng = AnalysisEngine(evidence)
    t = _task("scan.ports", {"port_scan": [
        {"target": "h1", "ports": [
            {"port": 3306, "protocol": "tcp", "service": "mysql",
             "risk": {"level": "high", "vulnerabilities": "exposed db"}}]}]})
    findings = eng.analyze_task(EngagementSession(target_id="t1"), t, target)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.validation_status == ValidationStatus.CONFIRMED
    assert f.evidence_ids and f.cvss_score > 0


def test_low_risk_ports_not_reported(evidence, target):
    eng = AnalysisEngine(evidence)
    t = _task("scan.ports", {"port_scan": [
        {"target": "h", "ports": [
            {"port": 80, "service": "http", "risk": {"level": "low"}}]}]})
    assert eng.analyze_task(EngagementSession(target_id="t1"), t, target) == []


def test_missing_headers_confirmed(evidence, target):
    eng = AnalysisEngine(evidence)
    t = _task("http.headers",
              {"header_analysis": {"missing_headers": ["CSP", "HSTS", "X-Frame-Options"]}})
    findings = eng.analyze_task(EngagementSession(target_id="t1"), t, target)
    assert findings[0].category == VulnCategory.MISSING_HEADERS
    assert findings[0].validation_status == ValidationStatus.CONFIRMED


def test_tls_expired_confirmed(evidence, target):
    eng = AnalysisEngine(evidence)
    t = _task("tls.inspect", {"tls": {"expired": True, "issuer": "X"}})
    findings = eng.analyze_task(EngagementSession(target_id="t1"), t, target)
    assert findings[0].category == VulnCategory.TLS_WEAKNESS
    assert findings[0].severity == Severity.HIGH


def test_takeover_is_potential_not_confirmed(evidence, target):
    eng = AnalysisEngine(evidence)
    t = _task("recon.takeover", {"takeover_analysis": {
        "vulnerable": [{"subdomain": "old.example.com", "service": "GitHub Pages"}]}})
    findings = eng.analyze_task(EngagementSession(target_id="t1"), t, target)
    assert findings[0].validation_status == ValidationStatus.POTENTIAL


def test_confirmed_requires_evidence(target):
    # evidence disabled -> no evidence ids -> CONFIRMED finding fails invariant
    eng = AnalysisEngine(EvidenceStore(enabled=False))
    t = _task("tls.inspect", {"tls": {"expired": True}})
    findings = eng.analyze_task(EngagementSession(target_id="t1"), t, target)
    assert findings == []  # dropped by is_consistent() filter


def test_finalize_dedupes_and_sorts(evidence, target):
    eng = AnalysisEngine(evidence)
    session = EngagementSession(target_id="t1")
    for _ in range(2):  # duplicate the same finding twice
        session.findings.extend(eng.analyze_task(
            session, _task("tls.inspect", {"tls": {"expired": True}}), target))
    summary = eng.finalize(session)
    assert len(session.findings) == 1   # deduped
    assert summary["confirmed"] >= 1
