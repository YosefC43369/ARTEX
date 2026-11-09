import pytest

from penetration_testing.exceptions import (
    PermissionDenied,
    RateLimitExceeded,
    ScopeViolation,
)
from penetration_testing.security.scope_manager import RateLimiter


def test_authorize_known_and_unknown(scope):
    assert scope.authorize_target("t1").identifier == "t1"
    with pytest.raises(ScopeViolation):
        scope.authorize_target("ghost")


def test_capability_fail_closed(scope, target):
    scope.require_capability(target, "recon")  # granted
    with pytest.raises(PermissionDenied):
        scope.require_capability(target, "port_scan")  # not granted


def test_host_in_scope(scope, target):
    assert scope.is_host_in_scope(target, "example.com")
    assert scope.is_host_in_scope(target, "api.example.com")  # wildcard on
    assert not scope.is_host_in_scope(target, "evil.com")
    assert not scope.is_host_in_scope(target, "example.com.evil.com")


def test_validate_url_rules(scope, target):
    assert scope.validate_url(target, "https://example.com/x")
    with pytest.raises(ScopeViolation):   # bad scheme
        scope.validate_url(target, "http://example.com/")
    with pytest.raises(ScopeViolation):   # out-of-scope host
        scope.validate_url(target, "https://evil.com/")
    with pytest.raises(ScopeViolation):   # excluded path
        scope.validate_url(target, "https://example.com/admin/panel")
    with pytest.raises(ScopeViolation):   # bad port
        scope.validate_url(target, "https://example.com:8443/")


def test_dns_resolution_blocks_private_ip(scope, target, monkeypatch):
    # in-scope name that resolves to loopback must be rejected (scope escape)
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda host, *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    with pytest.raises(ScopeViolation):
        scope.resolve_and_validate(target, "example.com")


def test_dns_resolution_allows_public_ip(scope, target, monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda host, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    ips = scope.resolve_and_validate(target, "example.com")
    assert ips == ["93.184.216.34"]


def test_redirect_revalidated(scope, target):
    # redirect to out-of-scope host is rejected
    with pytest.raises(ScopeViolation):
        scope.validate_redirect(target, "https://evil.com/", "https://example.com/")


def test_rate_limiter_enforces_budget():
    rl = RateLimiter(rate_per_second=1000, burst=2)
    assert rl.try_acquire() and rl.try_acquire()
    assert rl.try_acquire() is False  # burst exhausted immediately


def test_rate_limiter_acquire_timeout():
    rl = RateLimiter(rate_per_second=1000, burst=1)
    rl.try_acquire()
    with pytest.raises(RateLimitExceeded):
        rl.acquire(timeout=0.0)
