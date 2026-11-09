"""Integration: the subsystem is wired into app.py without regressing it."""

import pytest


@pytest.fixture(scope="module")
def client():
    import app
    return app.app.test_client()


def test_pentest_routes_registered(client):
    import app
    rules = {r.rule for r in app.app.url_map.iter_rules()}
    for r in ("/pentest/health", "/pentest/targets", "/pentest/capabilities",
              "/pentest/start", "/pentest/status/<session_id>",
              "/pentest/report/<session_id>", "/pentest/cancel/<session_id>"):
        assert r in rules


def test_health_and_targets(client):
    h = client.get("/pentest/health")
    assert h.status_code == 200
    assert h.get_json()["status"] == "healthy"
    targets = client.get("/pentest/targets").get_json()["targets"]
    # config.xml uses the simple URL-only form; id defaults to the host
    assert any(t["identifier"] == "example.com" for t in targets)


def test_capabilities(client):
    caps = client.get("/pentest/capabilities").get_json()["capabilities"]
    assert len(caps) >= 1
    assert all("permission" in c for c in caps)


def test_start_validation_and_scope(client):
    assert client.post("/pentest/start", json={}).status_code == 400
    assert client.post("/pentest/start", json={"target_id": "ghost"}).status_code == 404
    assert client.get("/pentest/status/ghost").status_code == 404


def test_no_regression_to_existing_routes(client):
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
    assert client.get("/about").status_code == 200


def test_openrouter_client_reused(client):
    import app
    from penetration_testing.llm_client import OpenRouterClient
    assert isinstance(app.pentest_agent.llm, OpenRouterClient)
