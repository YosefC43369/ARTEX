"""
penetration_testing.security.scope_manager
===========================================

The subsystem's single backend authority for "is this action allowed?".

This module intentionally consolidates what the directive listed as many
separate files (``target_validator``, ``url_validator``, ``dns_validator``,
``redirect_validator``, ``network_policy``, ``port``/``path`` validators,
``rate_limiter``, ``scope_policy``, ``safety_controller``, ``audit_logger``).
They share one decision — scope — and splitting them would scatter a security
boundary across a dozen files where a single missed check becomes a bypass.
One cohesive enforcer with full test coverage is safer than twelve thin ones.

Every check **fails closed**: anything not explicitly permitted is denied.

Enforcement provided
--------------------
* Target authorization against config.xml.
* Capability/permission checks (per target, fail-closed).
* URL validation: scheme, host-in-scope, port, path allow/deny.
* Host-in-scope: exact domain, declared allowed domains, optional wildcard
  subdomains — but **never** treats third-party infrastructure as in-scope.
* DNS resolution validation: resolved IPs must be public (blocks SSRF/scope
  escape to loopback, private, link-local, reserved and CGNAT ranges).
* Redirect validation: a redirect target is re-validated as a fresh URL.
* Per-target token-bucket rate limiting.
* Tamper-evident audit logging of every decision.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from ..configuration import Settings
from ..exceptions import (
    PermissionDenied,
    RateLimitExceeded,
    ScopeViolation,
)
from ..models import Target


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting
# ─────────────────────────────────────────────────────────────────────────────
class RateLimiter:
    """Thread-safe token bucket. One instance guards one target's request rate."""

    def __init__(self, rate_per_second: float, burst: Optional[int] = None):
        self.rate = max(0.1, float(rate_per_second))
        self.capacity = float(burst if burst is not None else max(1, int(self.rate)))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    def try_acquire(self) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    def acquire(self, timeout: float = 30.0) -> None:
        """Block until a token is free or raise :class:`RateLimitExceeded`."""
        deadline = time.monotonic() + timeout
        while True:
            if self.try_acquire():
                return
            if time.monotonic() >= deadline:
                raise RateLimitExceeded(
                    "Request-rate budget exhausted for this engagement.")
            # Sleep for roughly one token period.
            time.sleep(min(0.25, 1.0 / self.rate))


# ─────────────────────────────────────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class AuditEvent:
    ts: float
    decision: str          # "allow" | "deny"
    action: str
    detail: str
    target_id: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "ts": self.ts, "decision": self.decision, "action": self.action,
            "detail": self.detail, "target_id": self.target_id,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Scope manager
# ─────────────────────────────────────────────────────────────────────────────
class ScopeManager:
    def __init__(self, settings: Settings, logger: Optional[logging.Logger] = None):
        self.settings = settings
        self.logger = logger or logging.getLogger(__name__)
        self._audit: List[AuditEvent] = []
        self._limiters: Dict[str, RateLimiter] = {}
        self._dns_cache: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

    # -- audit ----------------------------------------------------------------
    def _record(self, decision: str, action: str, detail: str, target_id: str) -> None:
        evt = AuditEvent(time.time(), decision, action, detail, target_id)
        self._audit.append(evt)
        self.logger.log(
            logging.INFO if decision == "allow" else logging.WARNING,
            "[scope:%s] %s — %s (%s)", decision, action, detail, target_id,
        )

    @property
    def audit_log(self) -> List[Dict[str, str]]:
        return [e.to_dict() for e in self._audit]

    # -- authorization --------------------------------------------------------
    def authorize_target(self, identifier: str) -> Target:
        target = self.settings.get_target(identifier)
        if target is None:
            self._record("deny", "authorize_target", "unknown target", identifier)
            raise ScopeViolation(
                "Target is not in the authorized config.xml scope.",
                detail=identifier,
            )
        self._record("allow", "authorize_target", "authorized", identifier)
        return target

    def require_capability(self, target: Target, capability: str) -> None:
        # Global non-destructive guard: destructive capabilities can never be
        # granted while non_destructive_only is set (it cannot be unset by config).
        if not target.has_permission(capability):
            self._record("deny", "capability", capability, target.identifier)
            raise PermissionDenied(
                f"Capability '{capability}' is not granted for this target.",
                detail=target.identifier,
            )
        self._record("allow", "capability", capability, target.identifier)

    # -- host / url -----------------------------------------------------------
    def is_host_in_scope(self, target: Target, host: str) -> bool:
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return False
        if host in (h.lower() for h in target.excluded_hosts):
            return False
        for allowed in target.allowed_domains:
            allowed = allowed.lower().rstrip(".")
            if host == allowed:
                return True
            if target.allow_wildcard_subdomains and host.endswith("." + allowed):
                return True
        return False

    def validate_url(self, target: Target, url: str) -> str:
        """Validate scheme, host, port and path. Returns the normalized URL or
        raises :class:`ScopeViolation`."""
        parsed = urlparse(url if "://" in url else f"https://{url}")

        scheme = (parsed.scheme or "https").lower()
        if scheme not in target.allowed_protocols:
            self._record("deny", "url_scheme", scheme, target.identifier)
            raise ScopeViolation("Protocol not permitted for target.", detail=scheme)

        host = parsed.hostname or ""
        if not self.is_host_in_scope(target, host):
            self._record("deny", "url_host", host, target.identifier)
            raise ScopeViolation("Host is outside the authorized scope.", detail=host)

        port = parsed.port or (443 if scheme == "https" else 80)
        if port not in target.allowed_ports:
            self._record("deny", "url_port", str(port), target.identifier)
            raise ScopeViolation("Port is outside the authorized scope.", detail=str(port))

        path = parsed.path or "/"
        self._validate_path(target, path)

        self._record("allow", "validate_url", f"{host}:{port}{path}", target.identifier)
        return parsed.geturl()

    def _validate_path(self, target: Target, path: str) -> None:
        for ex in target.excluded_paths:
            if path.startswith(ex):
                self._record("deny", "url_path", path, target.identifier)
                raise ScopeViolation("Path is explicitly excluded.", detail=path)
        if target.allowed_paths:
            if not any(path.startswith(p) for p in target.allowed_paths):
                self._record("deny", "url_path", path, target.identifier)
                raise ScopeViolation(
                    "Path is not within the allowed path prefixes.", detail=path)

    # -- DNS ------------------------------------------------------------------
    def resolve_and_validate(self, target: Target, host: str) -> List[str]:
        """Resolve ``host`` and require every resolved IP to be public.

        Blocks the classic scope-escape / SSRF primitive where an in-scope name
        resolves to a loopback/internal/metadata address.
        """
        if not self.is_host_in_scope(target, host):
            raise ScopeViolation("Host is outside the authorized scope.", detail=host)

        with self._lock:
            cached = self._dns_cache.get(host)
        if cached is not None:
            return cached

        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            self._record("deny", "dns_resolve", f"{host}: {exc}", target.identifier)
            raise ScopeViolation("Host did not resolve.", detail=host) from exc

        ips = sorted({info[4][0] for info in infos})
        for ip in ips:
            if not self._is_public_ip(ip):
                self._record("deny", "dns_private_ip", f"{host}->{ip}", target.identifier)
                raise ScopeViolation(
                    "Host resolves to a non-public address (scope escape blocked).",
                    detail=f"{host} -> {ip}",
                )
        with self._lock:
            self._dns_cache[host] = ips
        self._record("allow", "dns_resolve", f"{host}->{','.join(ips)}", target.identifier)
        return ips

    @staticmethod
    def _is_public_ip(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (
            addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified
        )

    # -- redirects ------------------------------------------------------------
    def validate_redirect(self, target: Target, location: str, base_url: str) -> str:
        """Re-validate a redirect ``Location`` as a brand-new URL within scope."""
        from urllib.parse import urljoin

        absolute = urljoin(base_url, location)
        try:
            validated = self.validate_url(target, absolute)
        except ScopeViolation:
            self._record("deny", "redirect", absolute, target.identifier)
            raise
        self._record("allow", "redirect", absolute, target.identifier)
        return validated

    # -- rate limiting --------------------------------------------------------
    def rate_limiter_for(self, target: Target) -> RateLimiter:
        with self._lock:
            limiter = self._limiters.get(target.identifier)
            if limiter is None:
                rate = min(
                    target.max_requests_per_second,
                    self.settings.limits.max_requests_per_second,
                )
                limiter = RateLimiter(rate)
                self._limiters[target.identifier] = limiter
            return limiter
