"""
penetration_testing.roles
==========================

Role-based testing — an ARTEX port of CyberStrikeAI's ``roles/*.yaml`` concept.

A **role** is a focused assessment persona that (a) narrows and orders which
capabilities an engagement runs and (b) supplies a short focus hint to the
planner/LLM. Roles never *widen* authorization — the capabilities a role can use
are always intersected with what the target's scope policy actually grants, so a
role can only ever make an engagement more focused, never more permissive.

Built-in roles map CyberStrikeAI's scenario roles (information gathering, web app
testing, infra, etc.) onto ARTEX's capability names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Role:
    identifier: str
    name: str
    description: str
    focus: str                         # hint passed to the planner/LLM
    capabilities: List[str]            # preferred capability order for this role
    icon: str = "🛡️"
    enabled: bool = True

    def to_dict(self) -> Dict[str, object]:
        return {
            "identifier": self.identifier, "name": self.name,
            "description": self.description, "focus": self.focus,
            "capabilities": list(self.capabilities), "icon": self.icon,
            "enabled": self.enabled,
        }


# Built-in role registry. Capability names match the module bridge's registry.
_BUILTIN: Dict[str, Role] = {
    r.identifier: r for r in [
        Role(
            identifier="recon-specialist",
            name="Reconnaissance Specialist",
            description="Passive attack-surface mapping and asset discovery.",
            focus="Map the attack surface: enumerate subdomains, DNS, and "
                  "technologies without touching active controls.",
            capabilities=["recon.subdomains", "recon.dns", "recon.tech", "recon.email"],
            icon="🔭",
        ),
        Role(
            identifier="web-app-tester",
            name="Web Application Tester",
            description="Web-layer posture: TLS, security headers, technologies.",
            focus="Assess the web application's transport and header hardening "
                  "and fingerprint its stack.",
            capabilities=["recon.tech", "tls.inspect", "http.headers"],
            icon="🌐",
        ),
        Role(
            identifier="infra-tester",
            name="Infrastructure Tester",
            description="Network/infra exposure: DNS, TLS, exposed services.",
            focus="Evaluate infrastructure exposure — DNS posture, TLS, and "
                  "reachable services.",
            capabilities=["recon.dns", "tls.inspect", "scan.ports"],
            icon="🖧",
        ),
        Role(
            identifier="takeover-hunter",
            name="Subdomain Takeover Hunter",
            description="Dangling DNS and subdomain-takeover exposure.",
            focus="Enumerate subdomains and hunt for dangling delegations that "
                  "could enable subdomain takeover.",
            capabilities=["recon.subdomains", "recon.takeover"],
            icon="🎯",
        ),
        Role(
            identifier="full-spectrum",
            name="Full-Spectrum Assessment",
            description="All permitted capabilities, breadth-first.",
            focus="Run a broad, non-destructive assessment across every "
                  "permitted capability.",
            capabilities=[
                "recon.subdomains", "recon.dns", "recon.tech", "tls.inspect",
                "http.headers", "recon.takeover", "recon.email", "scan.ports",
            ],
            icon="🛰️",
        ),
    ]
}

DEFAULT_ROLE = "full-spectrum"


class RoleManager:
    def __init__(self, roles: Optional[Dict[str, Role]] = None):
        self._roles = roles or dict(_BUILTIN)

    def list_roles(self) -> List[Role]:
        return [r for r in self._roles.values() if r.enabled]

    def get(self, identifier: Optional[str]) -> Role:
        if not identifier:
            return self._roles[DEFAULT_ROLE]
        role = self._roles.get(identifier)
        if role is None:
            raise KeyError(f"Unknown role: {identifier}")
        return role

    def capabilities_for(self, role: Role, permitted: List[str]) -> List[str]:
        """Role preference ∩ what scope actually permits, in the role's order.

        Any permitted capability the role did not list is appended after the
        role's preferred ones, so nothing authorized is silently dropped.
        """
        permitted_set = set(permitted)
        ordered = [c for c in role.capabilities if c in permitted_set]
        ordered += [c for c in permitted if c not in ordered]
        return ordered
