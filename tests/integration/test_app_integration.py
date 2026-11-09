"""Integration: subsystem wiring + authentication gate, without regressing app."""

import pytest


@pytest.fixture(scope="module")
def client():
    """An authenticated admin client with a validated AI-agent key."""
    import app
    c = app.app.test_client()
    # bootstrap the sole admin (first user) — this also logs the session in
    r = c.post('/setup', data={'username': 'admin', 'password': 'supersecret'})
    assert r.status_code in (302, 200)
    # create a key and unlock the AI panel for this session
    kr = c.post('/admin/keys', json={'label': 'test', 'valid_days': 30})
    key = kr.get_json()['key']['value']
    ur = c.post('/pentest/unlock', json={'key': key})
    assert ur.get_json()['ok'] is True
    return c


def test_pentest_routes_registered(client):
    import app
    rules = {r.rule for r in app.app.url_map.iter_rules()}
    for r in ("/pentest/health", "/pentest/start", "/login", "/setup",
              "/admin/keys", "/pentest/unlock"):
        assert r in rules


def test_health_and_targets(client):
    h = client.get("/pentest/health")
    assert h.status_code == 200
    assert h.get_json()["status"] == "healthy"
    targets = client.get("/pentest/targets").get_json()["targets"]
    assert any(t["identifier"] == "example.com" for t in targets)


def test_capabilities_include_active(client):
    caps = client.get("/pentest/capabilities").get_json()["capabilities"]
    names = {c["name"] for c in caps}
    assert "attack.web_vuln" in names and "attack.ssrf" in names


def test_start_validation_and_scope(client):
    assert client.post("/pentest/start", json={}).status_code == 400
    assert client.post("/pentest/start", json={"target_id": "ghost"}).status_code == 404


def test_no_regression_to_existing_routes(client):
    assert client.get("/health").status_code == 200   # public
    assert client.get("/").status_code == 200          # logged in
    assert client.get("/about").status_code == 200


def test_openrouter_client_reused(client):
    import app
    from penetration_testing.llm_client import OpenRouterClient
    assert isinstance(app.pentest_agent.llm, OpenRouterClient)


def test_requires_login(client):
    import app
    fresh = app.app.test_client()                      # no session
    assert fresh.get("/pentest/health").status_code == 401
    assert fresh.get("/", headers={"Accept": "text/html"}).status_code == 302


def test_ai_panel_requires_key(client):
    import app
    fresh = app.app.test_client()
    fresh.post("/login", data={"username": "admin", "password": "supersecret"})
    r = fresh.get("/pentest/health")                   # logged in, no key
    assert r.status_code == 403 and r.get_json().get("locked") is True


def test_non_admin_cannot_manage_keys(client):
    import app
    # admin creates a normal user
    client.post("/admin/accounts",
                json={"username": "analyst", "password": "analystpass", "role": "user"})
    user = app.app.test_client()
    user.post("/login", data={"username": "analyst", "password": "analystpass"})
    assert user.get("/admin/keys").status_code == 403   # keys are admin-only
