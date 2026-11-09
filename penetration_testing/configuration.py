"""
penetration_testing.configuration
==================================

Loads and validates the subsystem configuration from ``config.xml``.

Safety contract (all enforced here, in the backend — never left to prompts):

* **Fail closed.** A missing file, malformed XML, or a validation error raises
  :class:`ConfigurationError`; the subsystem will not start with an ambiguous
  policy.
* **Unlisted targets are denied.** There is no implicit/default target.
* **Ceilings clamp, never raise.** Any runtime limit in the file is clamped to
  the hard ``SAFETY_CEILINGS``; a config can make the engagement *safer*, never
  more permissive than the ceiling.
* **Capabilities fail closed.** A permission absent from the file is ``False``.

A standard-library XML parser is used with external-entity handling left at the
safe defaults of ``xml.etree.ElementTree`` (it does not resolve external
entities), mitigating XXE against the config file itself.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Prefer defusedxml (hardened against XXE / billion-laughs) when it is
# installed; otherwise fall back to the stdlib parser, which does not resolve
# external entities and rejects undefined entity references by default. The
# config file is user-authored and local, so this is defence-in-depth.
try:  # pragma: no cover - import-time branch
    from defusedxml import ElementTree as ET  # type: ignore
    _XML_HARDENED = True
except ImportError:  # pragma: no cover
    from xml.etree import ElementTree as ET  # type: ignore
    _XML_HARDENED = False

from .constants import SAFETY_CEILINGS
from .exceptions import ConfigurationError
from .models import Target

# Capabilities a target may be granted. Anything not here cannot be enabled.
KNOWN_CAPABILITIES = {
    "recon",                 # passive discovery (subdomains, dns, tech)
    "tls_inspection",
    "http_analysis",
    "header_analysis",
    "port_scan",             # active but non-destructive
    "subdomain_takeover",
    "active_web_testing",    # non-destructive injection *indicators* only
    "api_testing",
    "llm_planning",          # allow OpenRouter-assisted planning
}


def _as_bool(text: Optional[str], default: bool = False) -> bool:
    if text is None:
        return default
    return text.strip().lower() in ("1", "true", "yes", "on", "enabled")


def _as_float(text: Optional[str], default: float) -> float:
    try:
        return float(text) if text is not None else default
    except (TypeError, ValueError):
        return default


def _as_int(text: Optional[str], default: int) -> int:
    try:
        return int(text) if text is not None else default
    except (TypeError, ValueError):
        return default


def _split_csv(text: Optional[str]) -> List[str]:
    if not text:
        return []
    return [p.strip() for p in text.split(",") if p.strip()]


def _normalize_url(value: str) -> str:
    """Ensure a URL carries a scheme (default https)."""
    value = value.strip()
    return value if "://" in value else f"https://{value}"


@dataclass
class RuntimeLimits:
    max_iterations: int = 25
    max_runtime_seconds: int = 1200
    max_concurrency: int = 4
    max_requests_per_second: float = 2.0
    max_tasks: int = 200

    def clamp(self) -> "RuntimeLimits":
        """Clamp every field to the hard safety ceiling (never above)."""
        self.max_iterations = min(self.max_iterations, SAFETY_CEILINGS["max_iterations"])
        self.max_runtime_seconds = min(
            self.max_runtime_seconds, SAFETY_CEILINGS["max_runtime_seconds"])
        self.max_concurrency = min(self.max_concurrency, SAFETY_CEILINGS["max_concurrency"])
        self.max_requests_per_second = min(
            self.max_requests_per_second, SAFETY_CEILINGS["max_requests_per_second"])
        self.max_tasks = min(self.max_tasks, SAFETY_CEILINGS["max_tasks"])
        return self


@dataclass
class Settings:
    targets: Dict[str, Target] = field(default_factory=dict)
    limits: RuntimeLimits = field(default_factory=RuntimeLimits)
    autonomous_enabled: bool = False
    evidence_enabled: bool = True
    evidence_dir: Optional[str] = None
    report_formats: List[str] = field(default_factory=lambda: ["json", "markdown"])
    log_level: str = "INFO"
    non_destructive_only: bool = True     # cannot be disabled via config
    features: Dict[str, bool] = field(default_factory=dict)

    def get_target(self, identifier: str) -> Optional[Target]:
        return self.targets.get(identifier)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "targets": {k: v.to_dict() for k, v in self.targets.items()},
            "limits": self.limits.__dict__,
            "autonomous_enabled": self.autonomous_enabled,
            "evidence_enabled": self.evidence_enabled,
            "report_formats": self.report_formats,
            "log_level": self.log_level,
            "non_destructive_only": self.non_destructive_only,
            "features": self.features,
        }


DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.xml"
)


class ConfigLoader:
    """Parses and validates config.xml into a :class:`Settings` object."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or os.environ.get("ARTEX_PENTEST_CONFIG", DEFAULT_CONFIG_PATH)

    def load(self) -> Settings:
        if not os.path.isfile(self.path):
            raise ConfigurationError(
                "Penetration-testing config.xml not found — refusing to start "
                "without an explicit scope policy (fail-closed).",
                detail=self.path,
            )
        try:
            tree = ET.parse(self.path)
        except Exception as exc:  # ParseError, or defusedxml Entities/DTD-forbidden
            raise ConfigurationError(
                "config.xml is not valid or safe XML (fail-closed).",
                detail=str(exc),
            ) from exc

        root = tree.getroot()
        if root.tag != "artex_pentest":
            raise ConfigurationError(
                "config.xml root element must be <artex_pentest>.",
                detail=f"got <{root.tag}>",
            )

        settings = Settings()
        self._load_engagement(root, settings)
        self._load_targets(root, settings)

        if not settings.targets:
            raise ConfigurationError(
                "config.xml defines no authorized targets — nothing may be "
                "assessed (fail-closed)."
            )
        return settings

    # -- sections -------------------------------------------------------------
    def _load_engagement(self, root: ET.Element, settings: Settings) -> None:
        eng = root.find("engagement")
        if eng is None:
            # Engagement block is optional; defaults + ceilings apply.
            settings.limits = RuntimeLimits().clamp()
            return

        limits = RuntimeLimits(
            max_iterations=_as_int(eng.findtext("max_iterations"), 25),
            max_runtime_seconds=_as_int(eng.findtext("max_runtime_seconds"), 1200),
            max_concurrency=_as_int(eng.findtext("max_concurrency"), 4),
            max_requests_per_second=_as_float(eng.findtext("max_requests_per_second"), 2.0),
            max_tasks=_as_int(eng.findtext("max_tasks"), 200),
        ).clamp()
        settings.limits = limits

        settings.autonomous_enabled = _as_bool(eng.findtext("autonomous_enabled"), False)
        settings.evidence_enabled = _as_bool(eng.findtext("evidence_enabled"), True)
        settings.evidence_dir = eng.findtext("evidence_dir") or None
        fmts = _split_csv(eng.findtext("report_formats"))
        if fmts:
            settings.report_formats = [f.lower() for f in fmts]
        settings.log_level = (eng.findtext("log_level") or "INFO").upper()

        features = eng.find("features")
        if features is not None:
            for child in features:
                settings.features[child.tag] = _as_bool(child.text, False)

    def _load_targets(self, root: ET.Element, settings: Settings) -> None:
        container = root.find("targets")
        if container is None:
            return
        seen = set()
        for node in container.findall("target"):
            target = self._parse_target(node)
            if target.identifier in seen:
                raise ConfigurationError(
                    "Duplicate target identifier in config.xml (fail-closed).",
                    detail=target.identifier,
                )
            seen.add(target.identifier)
            settings.targets[target.identifier] = target

    @staticmethod
    def _collect_urls(node: ET.Element) -> List[str]:
        """Gather target URLs (url-only schema), preserving order, de-duped.

        Supports the current ``<urls><url>...</url></urls>`` multi-URL form and,
        for backward compatibility, a single top-level ``<url>`` and a legacy
        ``<domain>`` (promoted to an https URL).
        """
        urls: List[str] = []
        container = node.find("urls")
        if container is not None:
            for u in container.findall("url"):
                if u.text and u.text.strip():
                    urls.append(_normalize_url(u.text))
        single = node.findtext("url")          # direct child only (not inside <urls>)
        if single and single.strip():
            urls.append(_normalize_url(single))
        legacy_domain = node.findtext("domain")   # backward compat
        if legacy_domain and legacy_domain.strip():
            urls.append(_normalize_url(legacy_domain))

        seen, out = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def _parse_target(self, node: ET.Element) -> Target:
        identifier = (node.get("id") or node.findtext("id") or "").strip()
        if not identifier:
            raise ConfigurationError("A <target> is missing its id (fail-closed).")

        urls = self._collect_urls(node)
        if not urls:
            raise ConfigurationError(
                "Target has no <url> (fail-closed).", detail=identifier)
        url = urls[0]
        domain = urlparse(url).hostname or ""
        if not domain:
            raise ConfigurationError(
                "Target primary <url> has no host (fail-closed).",
                detail=f"{identifier}: {url}")

        protocols = _split_csv(node.findtext("allowed_protocols")) or ["https"]
        ports_raw = _split_csv(node.findtext("allowed_ports")) or ["443"]
        try:
            ports = [int(p) for p in ports_raw]
        except ValueError as exc:
            raise ConfigurationError(
                "allowed_ports must be integers (fail-closed).",
                detail=f"{identifier}: {ports_raw}",
            ) from exc

        permissions: Dict[str, bool] = {}
        perm_node = node.find("permissions")
        if perm_node is not None:
            for child in perm_node:
                if child.tag not in KNOWN_CAPABILITIES:
                    raise ConfigurationError(
                        "Unknown capability in target permissions (fail-closed).",
                        detail=f"{identifier}: {child.tag}",
                    )
                permissions[child.tag] = _as_bool(child.text, False)

        allowed_domains = _split_csv(node.findtext("allowed_domains"))
        for u in urls:
            host = urlparse(u).hostname
            if host and host not in allowed_domains:
                allowed_domains.append(host)

        return Target(
            identifier=identifier,
            url=url,
            domain=domain,
            urls=urls,
            allowed_domains=allowed_domains,
            allow_wildcard_subdomains=_as_bool(node.findtext("allow_wildcard_subdomains"), False),
            allowed_protocols=[p.lower() for p in protocols],
            allowed_ports=ports,
            allowed_paths=_split_csv(node.findtext("allowed_paths")),
            excluded_paths=_split_csv(node.findtext("excluded_paths")),
            excluded_hosts=_split_csv(node.findtext("excluded_hosts")),
            permissions=permissions,
            max_requests_per_second=_as_float(
                node.findtext("max_requests_per_second"), 2.0),
            max_concurrency=_as_int(node.findtext("max_concurrency"), 4),
        )


def load_settings(path: Optional[str] = None) -> Settings:
    """Convenience entry point used by the agent."""
    return ConfigLoader(path).load()
