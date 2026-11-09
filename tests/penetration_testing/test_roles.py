import pytest

from penetration_testing.roles import RoleManager, DEFAULT_ROLE


def test_builtin_roles_present():
    rm = RoleManager()
    ids = {r.identifier for r in rm.list_roles()}
    assert {"recon-specialist", "web-app-tester", "full-spectrum"} <= ids


def test_default_and_unknown_role():
    rm = RoleManager()
    assert rm.get(None).identifier == DEFAULT_ROLE
    with pytest.raises(KeyError):
        rm.get("no-such-role")


def test_capabilities_for_intersects_and_orders():
    rm = RoleManager()
    role = rm.get("recon-specialist")  # prefers recon.* capabilities
    permitted = ["tls.inspect", "recon.dns", "recon.subdomains"]
    caps = rm.capabilities_for(role, permitted)
    # role's preferred order first (recon.subdomains before recon.dns), then rest
    assert caps.index("recon.subdomains") < caps.index("recon.dns")
    assert "tls.inspect" in caps          # permitted-but-unlisted still kept
    assert set(caps) == set(permitted)    # never drops or adds authorization


def test_role_never_widens():
    rm = RoleManager()
    role = rm.get("full-spectrum")        # lists many capabilities
    permitted = ["recon.dns"]             # but only one is permitted
    assert rm.capabilities_for(role, permitted) == ["recon.dns"]
