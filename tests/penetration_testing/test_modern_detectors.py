from penetration_testing.constants import Phase, VulnCategory
from penetration_testing.evidence.evidence_store import EvidenceStore
from penetration_testing.intelligence.modern_detectors import ModernDetectors
from penetration_testing.models import EngagementSession, Target, Task


def _target():
    return Target(identifier="t1", url="https://example.com", domain="example.com")


def _session_with(result):
    s = EngagementSession(target_id="t1")
    t = Task(phase=Phase.TESTING, capability="attack.web_vuln")
    t.result = result
    s.tasks.append(t)
    return s


def test_graphql_exposure_detected():
    md = ModernDetectors(EvidenceStore(enabled=True))
    s = _session_with({"web_vuln": {"body": '{"data":{"__schema":{"queryType":{}}}}'}})
    finds = md.run(s, _target())
    gql = [f for f in finds if f.category == VulnCategory.GRAPHQL]
    assert gql and gql[0].cwe and gql[0].mitre


def test_idor_candidates_detected():
    md = ModernDetectors(EvidenceStore(enabled=True))
    s = _session_with({"web_vuln": {"urls": ["https://example.com/api/user?id=1001"]}})
    finds = md.run(s, _target())
    assert any(f.category == VulnCategory.IDOR for f in finds)


def test_mass_assignment_detected():
    md = ModernDetectors(EvidenceStore(enabled=True))
    s = _session_with({"web_vuln": {"body": '{"username":"x","is_admin":true}'}})
    finds = md.run(s, _target())
    assert any(f.category == VulnCategory.MASS_ASSIGNMENT for f in finds)


def test_no_indicators_no_findings():
    md = ModernDetectors(EvidenceStore(enabled=True))
    s = _session_with({"web_vuln": {"body": "a perfectly ordinary response"}})
    assert md.run(s, _target()) == []
