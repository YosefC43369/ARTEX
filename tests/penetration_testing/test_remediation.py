from penetration_testing.constants import (
    Severity,
    ValidationStatus,
    VulnCategory,
)
from penetration_testing.intelligence.remediation import RemediationAdvisor
from penetration_testing.models import Finding


def _finding(**kw):
    base = dict(target_id="t1", category=VulnCategory.SSRF, title="x",
                description="d", severity=Severity.HIGH,
                validation_status=ValidationStatus.CONFIRMED, evidence_ids=["e"])
    base.update(kw)
    return Finding(**base)


def test_enrich_fills_blank_fields():
    f = _finding()
    RemediationAdvisor().enrich(f)
    assert f.cwe == "CWE-918"
    assert f.mitre
    assert f.remediation
    assert f.references


def test_enrich_does_not_overwrite_existing_remediation():
    f = _finding(remediation="KEEP THIS")
    RemediationAdvisor().enrich(f)
    assert f.remediation == "KEEP THIS"      # analysis-supplied text wins


def test_enrich_preserves_status_and_severity():
    f = _finding(validation_status=ValidationStatus.POTENTIAL, severity=Severity.LOW)
    RemediationAdvisor().enrich(f)
    assert f.validation_status == ValidationStatus.POTENTIAL   # never promotes
    assert f.severity == Severity.LOW


def test_every_vuln_category_has_remediation_or_mapping():
    adv = RemediationAdvisor()
    for cat in VulnCategory:
        # either explicit remediation guidance or at least a CWE mapping exists
        rem = adv.advise(cat.value).as_text()
        cwe = adv.signatures.mapping(cat.value)["cwe"]
        assert rem or cwe, f"no guidance for {cat.value}"


def test_enrich_unknown_category_is_safe():
    # a finding whose category has no remediation entry must not crash
    f = _finding(category=VulnCategory.SUBDOMAIN_TAKEOVER, remediation="")
    RemediationAdvisor().enrich(f)
    assert f.cwe  # still stamped from the signature library
