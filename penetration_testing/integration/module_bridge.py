"""
penetration_testing.integration.module_bridge
==============================================

The controlled gateway between the autonomous subsystem and ARTEX's existing
reconnaissance / scanning / analysis modules.

This single module covers what the directive split into ``module_discovery``,
``adapter_manager``, ``interface_registry``, ``tool_router``,
``capability_registry``, ``compatibility_manager``, ``dependency_resolver`` and
``result_normalizer``. They are all steps of one pipeline — *register a known
module → check it's importable → validate scope → invoke it → normalize its
result* — and keeping them together makes the trust boundary auditable.

Security model (critical)
-------------------------
* **No arbitrary imports.** Only a curated allowlist of known-compatible ARTEX
  classes is registered, each behind a hand-written adapter with a known method
  signature. The bridge never imports or executes a module merely because it
  exists on disk.
* **Discovery = availability probing of that allowlist.** A capability is
  registered only if its backing module imports cleanly in this environment.
* **Every invocation inherits the engagement scope.** Before delegating, the
  bridge enforces the target's capability permission, re-validates the target
  host/URL against scope (including DNS resolution to a public IP), and spends a
  rate-limit token. A delegated module therefore cannot be used to act outside
  the authorized target.

Known limitation (documented honestly)
--------------------------------------
The existing ARTEX modules perform their own network I/O internally and do not
expose per-request hooks, so the bridge enforces scope at the *target* boundary
(authorized domain, capability, rate budget) rather than intercepting every
individual packet the delegated module emits. Tightening this to per-request
egress filtering would require refactoring those modules and is called out as
future work rather than silently assumed.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..configuration import Settings
from ..constants import EvidenceKind, Phase
from ..evidence.evidence_store import EvidenceStore
from ..exceptions import (
    IntegrationError,
    ModuleNotRegistered,
    PenTestError,
    ToolExecutionError,
)
from ..llm_client import OpenRouterClient
from ..models import Target, ToolResult
from ..security.scope_manager import ScopeManager


@dataclass
class InvocationContext:
    target: Target
    params: Dict[str, Any]
    scope: ScopeManager
    evidence: EvidenceStore
    llm: OpenRouterClient
    logger: logging.Logger
    task_id: str = "adhoc"


@dataclass
class CapabilitySpec:
    name: str
    phase: Phase
    permission: str                 # capability the target must grant
    description: str
    invoke: Callable[[InvocationContext], Dict[str, Any]]
    module_path: str = ""
    available: bool = True
    unavailable_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "phase": str(self.phase),
            "permission": self.permission, "description": self.description,
            "module": self.module_path, "available": self.available,
            "unavailable_reason": self.unavailable_reason,
        }


class ModuleBridge:
    def __init__(
        self,
        settings: Settings,
        scope: ScopeManager,
        evidence: EvidenceStore,
        llm: OpenRouterClient,
        logger: Optional[logging.Logger] = None,
    ):
        self.settings = settings
        self.scope = scope
        self.evidence = evidence
        self.llm = llm
        self.logger = logger or logging.getLogger(__name__)
        self._registry: Dict[str, CapabilitySpec] = {}
        self._register_builtin()

    # ── discovery / registration ────────────────────────────────────────────
    def _try_register(
        self, name: str, phase: Phase, permission: str, description: str,
        module_path: str, symbol: str, invoke: Callable[[InvocationContext], Dict[str, Any]],
    ) -> None:
        """Register a capability only if its backing ARTEX class imports."""
        available, reason = True, ""
        try:
            mod = __import__(module_path, fromlist=[symbol])
            if not hasattr(mod, symbol):
                available, reason = False, f"{symbol} not found in {module_path}"
        except Exception as exc:  # ImportError or dependency failure
            available, reason = False, f"import failed: {exc}"
        spec = CapabilitySpec(
            name=name, phase=phase, permission=permission, description=description,
            invoke=invoke, module_path=f"{module_path}.{symbol}",
            available=available, unavailable_reason=reason,
        )
        self._registry[name] = spec
        if not available:
            self.logger.warning("Capability '%s' unavailable: %s", name, reason)

    def _register_builtin(self) -> None:
        self._try_register(
            "recon.subdomains", Phase.RECON, "recon",
            "Enumerate subdomains via existing SubdomainEnumerator.",
            "modules.subdomains", "SubdomainEnumerator", self._invoke_subdomains)
        self._try_register(
            "recon.dns", Phase.RECON, "recon",
            "Collect DNS records via existing DNSScanner.",
            "modules.dns_scan", "DNSScanner", self._invoke_dns)
        self._try_register(
            "recon.tech", Phase.RECON, "recon",
            "Fingerprint technologies via existing TechnologyDetector.",
            "modules.tech_detector", "TechnologyDetector", self._invoke_tech)
        self._try_register(
            "recon.email", Phase.ENUMERATION, "recon",
            "Discover email/user patterns via existing EmailUserEnumerator.",
            "modules.enumeration", "EmailUserEnumerator", self._invoke_email)
        self._try_register(
            "tls.inspect", Phase.ANALYSIS, "tls_inspection",
            "Inspect TLS/SSL configuration via existing SSLScanner.",
            "modules.ssl_scanner", "SSLScanner", self._invoke_tls)
        self._try_register(
            "http.headers", Phase.ANALYSIS, "header_analysis",
            "Analyze security headers via existing AIHeaderAnalyzer.",
            "modules.AI_header_analyzer", "AIHeaderAnalyzer", self._invoke_headers)
        self._try_register(
            "recon.takeover", Phase.ANALYSIS, "subdomain_takeover",
            "Assess subdomain takeover exposure via existing analyzer.",
            "modules.AI_subdomain_takeover_analyzer", "AISubdomainTakeoverAnalyzer",
            self._invoke_takeover)
        self._try_register(
            "scan.ports", Phase.TESTING, "port_scan",
            "Scan common ports via existing PortScanner.",
            "modules.port_scanner", "PortScanner", self._invoke_ports)

        # ── active / offensive capabilities (red-team) ───────────────────────
        self._try_register(
            "attack.web_vuln", Phase.TESTING, "web_vuln",
            "Active web vulnerability scan via existing WebVulnScanner.",
            "modules.web_vuln_scanner", "WebVulnScanner", self._invoke_web_vuln)
        self._try_register(
            "attack.dir_bruteforce", Phase.TESTING, "dir_bruteforce",
            "Directory/content brute-force via existing DirectoryBruteforcer.",
            "modules.dir_bruteforce", "DirectoryBruteforcer", self._invoke_dir_bruteforce)
        self._try_register(
            "attack.bypass_403", Phase.TESTING, "bypass_403",
            "Access-control (403) bypass probing via existing Bypass403Scanner.",
            "modules.bypass_403", "Bypass403Scanner", self._invoke_bypass_403)
        self._try_register(
            "attack.ssti", Phase.TESTING, "ssti",
            "Server-side template injection testing via existing SSTIScanner.",
            "modules.ssti_scanner", "SSTIScanner", self._invoke_ssti)
        self._try_register(
            "attack.jwt", Phase.TESTING, "jwt_analysis",
            "JWT weakness analysis via existing JWTAnalyzer.",
            "modules.jwt_analyzer", "JWTAnalyzer", self._invoke_jwt)
        self._try_register(
            "attack.db_files", Phase.TESTING, "db_file_hunt",
            "Exposed database/backup file hunting via existing DBFileHunter.",
            "modules.db_file_hunter", "DBFileHunter", self._invoke_db_files)
        self._try_register(
            "attack.cors", Phase.TESTING, "cors_test",
            "CORS misconfiguration testing via existing CorsTester.",
            "core.cors_tester", "CorsTester", self._invoke_cors)
        self._try_register(
            "attack.ssrf", Phase.TESTING, "ssrf_test",
            "SSRF probing via existing SsrfProbe.",
            "core.ssrf_probe", "SsrfProbe", self._invoke_ssrf)
        self._try_register(
            "attack.xxe", Phase.TESTING, "xxe_test",
            "XXE injection testing via existing XxeInjector.",
            "core.xxe_injector", "XxeInjector", self._invoke_xxe)
        self._try_register(
            "attack.lfi", Phase.TESTING, "lfi_test",
            "Local/remote file inclusion testing via existing LfiRfi.",
            "core.lfi_rfi", "LfiRfi", self._invoke_lfi)
        self._try_register(
            "attack.auth_bypass", Phase.TESTING, "auth_bypass",
            "Authentication bypass testing via existing AuthBypass.",
            "core.auth_bypass", "AuthBypass", self._invoke_auth_bypass)
        self._try_register(
            "attack.vuln_scan", Phase.TESTING, "vuln_scan",
            "Injection/access-control vulnerability scan via existing VulnScanner.",
            "core.vuln_scanner", "VulnScanner", self._invoke_vuln_scan)

    # ── public API ──────────────────────────────────────────────────────────
    def list_capabilities(self, available_only: bool = True) -> List[CapabilitySpec]:
        specs = list(self._registry.values())
        return [s for s in specs if s.available] if available_only else specs

    def has(self, name: str) -> bool:
        spec = self._registry.get(name)
        return bool(spec and spec.available)

    def invoke(
        self, name: str, target: Target, params: Optional[Dict[str, Any]] = None,
        task_id: str = "adhoc",
    ) -> ToolResult:
        """Scope-checked, rate-limited, evidence-recording invocation."""
        spec = self._registry.get(name)
        if spec is None:
            raise ModuleNotRegistered("No such capability.", detail=name)
        if not spec.available:
            raise IntegrationError(
                "Capability backing module is unavailable.",
                detail=f"{name}: {spec.unavailable_reason}")

        # 1. permission + scope enforcement BEFORE any delegation
        self.scope.require_capability(target, spec.permission)
        self.scope.validate_url(target, target.url)
        self.scope.resolve_and_validate(target, target.domain)
        # 2. spend a rate-limit token for the engagement
        self.scope.rate_limiter_for(target).acquire()

        ctx = InvocationContext(
            target=target, params=params or {}, scope=self.scope,
            evidence=self.evidence, llm=self.llm, logger=self.logger, task_id=task_id,
        )
        started = time.monotonic()
        try:
            data = spec.invoke(ctx)
            duration = round(time.monotonic() - started, 3)
            self.evidence.record(
                target_id=target.identifier, task_id=task_id,
                kind=EvidenceKind.TOOL_OUTPUT,
                summary=f"{name} completed",
                data={"capability": name, "keys": list(data.keys())[:20]},
            )
            return ToolResult(ok=True, capability=name, data=data, duration_s=duration)
        except PenTestError:
            raise
        except Exception as exc:  # delegated module raised
            duration = round(time.monotonic() - started, 3)
            self.logger.exception("Capability '%s' raised", name)
            raise ToolExecutionError(
                f"Delegated module for '{name}' failed.", detail=str(exc)) from exc

    # ── adapters (known, hand-written; one per registered capability) ────────
    def _invoke_subdomains(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.subdomains import SubdomainEnumerator
        subs = SubdomainEnumerator().enumerate(ctx.target.domain)
        return {"subdomains": subs, "count": len(subs) if subs else 0}

    def _invoke_dns(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.dns_scan import DNSScanner
        records = DNSScanner(ctx.target.domain).scan(
            aggressive=bool(ctx.params.get("aggressive", False)))
        return {"dns_records": records}

    def _invoke_tech(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.tech_detector import TechnologyDetector
        url = ctx.params.get("url", ctx.target.url)
        self.scope.validate_url(ctx.target, url)
        tech = TechnologyDetector().detect_technologies(url)
        return {"technologies": tech, "url": url}

    def _invoke_email(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.enumeration import EmailUserEnumerator
        return {"email_enumeration": EmailUserEnumerator().find_email_patterns(ctx.target.domain)}

    def _invoke_tls(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.ssl_scanner import SSLScanner
        host = ctx.params.get("host", ctx.target.domain)
        if not self.scope.is_host_in_scope(ctx.target, host):
            host = ctx.target.domain
        return {"tls": SSLScanner().scan(host)}

    def _invoke_headers(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.AI_header_analyzer import AIHeaderAnalyzer
        analyzer = AIHeaderAnalyzer(openrouter_api_key=self.llm.api_key)
        subs = ctx.params.get("subdomains") or []
        return {"header_analysis": analyzer.analyze(
            ctx.target.domain, subdomains=subs,
            max_targets=int(ctx.params.get("max_targets", 5)))}

    def _invoke_takeover(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.AI_subdomain_takeover_analyzer import AISubdomainTakeoverAnalyzer
        analyzer = AISubdomainTakeoverAnalyzer(openrouter_api_key=self.llm.api_key)
        subs = ctx.params.get("subdomains") or []
        return {"takeover_analysis": analyzer.analyze(
            ctx.target.domain, subdomains=subs,
            max_targets=int(ctx.params.get("max_targets", 10)))}

    def _invoke_ports(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.port_scanner import PortScanner
        ports = ctx.params.get("ports", "80,443,8080,8443")
        results = PortScanner().batch_scan([ctx.target.domain], ports=ports)
        return {"port_scan": [r for r in (results or []) if r is not None]}

    # ── active / offensive adapters ──────────────────────────────────────────
    def _invoke_web_vuln(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.web_vuln_scanner import WebVulnScanner
        return {"web_vuln": WebVulnScanner(target_url=ctx.target.url).scan(ctx.target.domain)}

    def _invoke_dir_bruteforce(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.dir_bruteforce import DirectoryBruteforcer
        return {"dir_bruteforce": DirectoryBruteforcer(
            target_url=ctx.target.url, recursive=False, max_workers=20).scan()}

    def _invoke_bypass_403(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.bypass_403 import Bypass403Scanner
        return {"bypass_403": Bypass403Scanner(
            target_url=ctx.target.url,
            known_403_urls=ctx.params.get("known_403", []), max_workers=20).scan()}

    def _invoke_ssti(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.ssti_scanner import SSTIScanner
        return {"ssti": SSTIScanner(
            target_url=ctx.target.url, known_params=ctx.params.get("known_params", {}),
            rate_delay=0.2, max_workers=12).scan()}

    def _invoke_jwt(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.jwt_analyzer import JWTAnalyzer
        return {"jwt": JWTAnalyzer(
            target_url=ctx.target.url, known_tokens=ctx.params.get("known_tokens", []),
            rate_delay=0.2, max_workers=12).scan()}

    def _invoke_db_files(self, ctx: InvocationContext) -> Dict[str, Any]:
        from modules.db_file_hunter import DBFileHunter
        return {"db_files": DBFileHunter(target_url=ctx.target.url, max_workers=16).scan()}

    def _invoke_cors(self, ctx: InvocationContext) -> Dict[str, Any]:
        from core.cors_tester import CorsTester
        return {"cors": CorsTester().run(domain=ctx.target.domain, scan_results={})}

    def _invoke_ssrf(self, ctx: InvocationContext) -> Dict[str, Any]:
        from core.ssrf_probe import SsrfProbe
        return {"ssrf": SsrfProbe().run(domain=ctx.target.domain, scan_results={})}

    def _invoke_xxe(self, ctx: InvocationContext) -> Dict[str, Any]:
        from core.xxe_injector import XxeInjector
        return {"xxe": XxeInjector().run(domain=ctx.target.domain, scan_results={})}

    def _invoke_lfi(self, ctx: InvocationContext) -> Dict[str, Any]:
        from core.lfi_rfi import LfiRfi
        return {"lfi": LfiRfi().run(domain=ctx.target.domain, scan_results={})}

    def _invoke_auth_bypass(self, ctx: InvocationContext) -> Dict[str, Any]:
        from core.auth_bypass import AuthBypass
        return {"auth_bypass": AuthBypass().run(domain=ctx.target.domain, scan_results={})}

    def _invoke_vuln_scan(self, ctx: InvocationContext) -> Dict[str, Any]:
        from core.vuln_scanner import VulnScanner
        return {"vuln_scan": VulnScanner().run(domain=ctx.target.domain, scan_results={})}
