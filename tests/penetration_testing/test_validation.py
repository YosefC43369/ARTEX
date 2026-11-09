from penetration_testing.constants import (
    EvidenceKind,
    ValidationStatus,
    VulnCategory,
)
from penetration_testing.evidence.evidence_store import EvidenceStore
from penetration_testing.intelligence.validation import FindingValidator
from penetration_testing.models import Finding


def test_injection_without_evidence_is_false_positive():
    v = FindingValidator(EvidenceStore(enabled=True))
    f = Finding(target_id="t1", category=VulnCategory.SSRF, title="x", description="",
                validation_status=ValidationStatus.POTENTIAL)   # no evidence
    v.validate(f)
    assert f.validation_status == ValidationStatus.FALSE_POSITIVE
    assert f.fp_reason


def test_corroborated_potential_is_promoted():
    store = EvidenceStore(enabled=True)
    ev = store.record(target_id="t1", task_id="x", kind=EvidenceKind.OBSERVATION,
                      summary="resp",
                      response_excerpt="reached 169.254.169.254 iam/security-credentials")
    f = Finding(target_id="t1", category=VulnCategory.SSRF, title="ssrf", description="d",
                evidence_ids=[ev.evidence_id],
                validation_status=ValidationStatus.POTENTIAL)
    FindingValidator(store).validate(f)
    assert f.validation_status == ValidationStatus.CONFIRMED
    assert f.cwe == "CWE-918" and f.mitre


def test_cwe_stamped_on_confirmed():
    store = EvidenceStore(enabled=True)
    f = Finding(target_id="t1", category=VulnCategory.MISSING_HEADERS, title="h",
                description="d", evidence_ids=["e"],
                validation_status=ValidationStatus.CONFIRMED)
    FindingValidator(store).validate(f)
    assert f.cwe == "CWE-693"
    assert f.validation_status == ValidationStatus.CONFIRMED


def test_batch_removes_false_positives():
    store = EvidenceStore(enabled=True)
    fps = [Finding(target_id="t1", category=VulnCategory.SSRF, title=f"x{i}",
                   description="", validation_status=ValidationStatus.POTENTIAL)
           for i in range(3)]
    kept, stats = FindingValidator(store).validate_findings(fps)
    assert stats["false_positives_removed"] == 3
    assert kept == []
