import pytest

from penetration_testing.exceptions import ModuleNotRegistered, PermissionDenied
from penetration_testing.integration.module_bridge import ModuleBridge


@pytest.fixture
def bridge(settings, scope, evidence, llm):
    return ModuleBridge(settings, scope, evidence, llm)


def test_capabilities_registered(bridge):
    names = {s.name for s in bridge.list_capabilities(available_only=False)}
    assert "recon.subdomains" in names
    assert "tls.inspect" in names
    assert bridge.has("recon.subdomains")


def test_active_capabilities_registered(bridge):
    names = {s.name for s in bridge.list_capabilities(available_only=False)}
    # the offensive arsenal is wired from the existing ARTEX modules
    for cap in ("attack.web_vuln", "attack.ssrf", "attack.ssti",
                "attack.cors", "attack.auth_bypass", "attack.dir_bruteforce"):
        assert cap in names


def test_unknown_capability_raises(bridge, target):
    with pytest.raises(ModuleNotRegistered):
        bridge.invoke("does.not.exist", target)


def test_invoke_denied_without_permission(bridge, target):
    # target does not grant 'port_scan' -> scope denies before any delegation
    with pytest.raises(PermissionDenied):
        bridge.invoke("scan.ports", target)


def test_invoke_success_with_mocked_module(bridge, target, monkeypatch):
    # block real DNS + real recon
    monkeypatch.setattr("socket.getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    monkeypatch.setattr(
        "modules.subdomains.SubdomainEnumerator.enumerate",
        lambda self, domain: [{"subdomain": f"www.{domain}", "ip": "93.184.216.34"}],
    )
    result = bridge.invoke("recon.subdomains", target, task_id="task-x")
    assert result.ok is True
    assert result.data["count"] == 1
    assert result.data["subdomains"][0]["subdomain"] == "www.example.com"
    # evidence was recorded for the tool invocation
    assert any(e.task_id == "task-x" for e in bridge.evidence.all())
