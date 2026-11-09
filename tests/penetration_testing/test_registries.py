from penetration_testing.constants import Severity, ValidationStatus, VulnCategory
from penetration_testing.models import EngagementSession, Finding, Phase, Task
from penetration_testing.storage.asset_registry import AssetRegistry
from penetration_testing.storage.finding_registry import FindingRegistry


# ── assets ───────────────────────────────────────────────────────────────────
def test_asset_normalize_and_dedup():
    r = AssetRegistry()
    r.add("host", "WWW.Example.com.")
    a = r.add("host", "www.example.com")   # same after normalization
    assert a.observations == 2
    assert r.add("ip", "not-an-ip") is None
    assert r.add("ip", "93.184.216.34").value == "93.184.216.34"
    assert r.add("port", "70000") is None   # out of range
    assert r.stats()["host"] == 1


def test_asset_ingest_session():
    r = AssetRegistry()
    s = EngagementSession(target_id="t1")
    t = Task(phase=Phase.RECON, capability="recon.subdomains")
    t.result = {"subdomains": [{"subdomain": "a.example.com", "ip": "1.1.1.1"}]}
    s.tasks.append(t)
    tp = Task(phase=Phase.TESTING, capability="scan.ports")
    tp.result = {"port_scan": [{"target": "a.example.com",
                                "ports": [{"port": 443, "service": "https"}]}]}
    s.tasks.append(tp)
    r.ingest_session(s)
    kinds = r.stats()
    assert kinds["host"] >= 1 and kinds["ip"] >= 1 and kinds["port"] >= 1


# ── findings / vulnerability lifecycle ───────────────────────────────────────
def _finding(title="Expired cert", status=ValidationStatus.CONFIRMED):
    return Finding(target_id="t1", category=VulnCategory.TLS_WEAKNESS, title=title,
                   description="d", endpoint="example.com", severity=Severity.HIGH,
                   validation_status=status, evidence_ids=["e1"])


def test_finding_ingest_and_dedup():
    reg = FindingRegistry()
    r1 = reg.ingest([_finding()], "s1")
    assert r1["new"] == 1
    r2 = reg.ingest([_finding()], "s2")   # same signature
    assert r2["new"] == 0 and r2["updated"] == 1
    rec = reg.all()[0]
    assert rec.occurrences == 2
    assert rec.state == "confirmed"       # CONFIRMED starts at 'confirmed'


def test_finding_lifecycle_and_filter():
    reg = FindingRegistry()
    reg.ingest([_finding(title="A"), _finding(title="B")], "s1")
    rec = reg.all()[0]
    reg.set_state(rec.signature, "resolved", note="patched")
    assert reg.filter(state="resolved")
    assert reg.filter(severity="high")
    stats = reg.stats()
    assert stats["total"] == 2
    assert stats["by_state"]["resolved"] == 1


def test_invalid_state_rejected():
    reg = FindingRegistry()
    reg.ingest([_finding()], "s1")
    sig = reg.all()[0].signature
    import pytest
    with pytest.raises(ValueError):
        reg.set_state(sig, "bogus_state")
