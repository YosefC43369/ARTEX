"""
penetration_testing.intelligence.planner
=========================================

Turns an authorized target plus the set of *available & permitted* capabilities
into an ordered, bounded list of :class:`~penetration_testing.models.Task`
objects, and revises that plan as evidence arrives.

Consolidates the directive's ``planner`` / ``reasoning_engine`` /
``hypothesis_engine`` / ``decision_engine`` planning concerns. It is
LLM-assisted but **never LLM-dependent**: with no OpenRouter key (or on any
parse failure) it falls back to a deterministic, phase-ordered plan, matching
ARTEX's existing rule-based-fallback philosophy.

The LLM is only ever allowed to *reorder/select among already-permitted
capabilities* — it can never introduce a capability the scope policy has not
granted. Authorization is enforced upstream of the model, never by it.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Dict, List, Optional

from ..constants import Phase
from ..llm_client import OpenRouterClient
from ..models import EngagementSession, Target, Task

# Deterministic baseline order (phase-sensible). Only capabilities that are both
# available in the bridge and permitted for the target survive filtering.
_DEFAULT_ORDER = [
    "recon.subdomains",
    "recon.dns",
    "recon.tech",
    "tls.inspect",
    "http.headers",
    "recon.takeover",
    "recon.email",
    "scan.ports",
]

def apply_default_order(capabilities: List[str]) -> List[str]:
    """Order capabilities by the phase-sensible default, keeping extras last."""
    ordered = [c for c in _DEFAULT_ORDER if c in capabilities]
    ordered += [c for c in capabilities if c not in ordered]
    return ordered


_PHASE_BY_CAP = {
    "recon.subdomains": Phase.RECON,
    "recon.dns": Phase.RECON,
    "recon.tech": Phase.RECON,
    "recon.email": Phase.ENUMERATION,
    "tls.inspect": Phase.ANALYSIS,
    "http.headers": Phase.ANALYSIS,
    "recon.takeover": Phase.ANALYSIS,
    "scan.ports": Phase.TESTING,
}


class Planner:
    def __init__(self, llm: OpenRouterClient, logger: Optional[logging.Logger] = None):
        self.llm = llm
        self.logger = logger or logging.getLogger(__name__)

    def build_plan(
        self, target: Target, capabilities: List[str], max_tasks: int,
    ) -> List[Task]:
        # Preserve the caller's order (the orchestrator has already applied the
        # role ordering, or the default order when no role is set).
        ordered = list(capabilities)

        if self.llm.available:
            llm_order = self._llm_prioritize(target, ordered)
            if llm_order:
                ordered = llm_order

        tasks: List[Task] = []
        for cap in ordered[:max_tasks]:
            tasks.append(Task(
                phase=_PHASE_BY_CAP.get(cap, Phase.ANALYSIS),
                capability=cap,
                description=f"Run {cap} against {target.identifier}",
            ))
        self.logger.info("Planned %d task(s) for %s", len(tasks), target.identifier)
        return tasks

    def _llm_prioritize(self, target: Target, capabilities: List[str]) -> Optional[List[str]]:
        prompt = (
            "You are planning an AUTHORIZED, non-destructive security assessment.\n"
            f"Target domain: {target.domain}\n"
            f"Available capabilities (you may ONLY choose from these, never add "
            f"others): {capabilities}\n\n"
            "Return a JSON array ordering these capability names from most to "
            "least valuable to run first for safe reconnaissance and analysis. "
            "Respond with ONLY the JSON array."
        )
        text = self.llm.complete(prompt, temperature=0.2, max_tokens=400)
        if not text:
            return None
        try:
            match = re.search(r"\[.*\]", text, re.DOTALL)
            if not match:
                return None
            parsed = json.loads(match.group(0))
            # keep only known/permitted capabilities; preserve any dropped ones
            filtered = [c for c in parsed if c in capabilities]
            for c in capabilities:
                if c not in filtered:
                    filtered.append(c)
            return filtered or None
        except (json.JSONDecodeError, TypeError) as exc:
            self.logger.warning("LLM plan parse failed, using deterministic order: %s", exc)
            return None

    def replan(
        self, session: EngagementSession, target: Target,
        capabilities: List[str], max_tasks: int,
    ) -> List[Task]:
        """Add follow-up tasks when evidence changes the picture.

        Concretely: once subdomains are discovered, feed them into the header
        and takeover capabilities (bounded by ``max_tasks``).
        """
        existing = {t.capability for t in session.tasks}
        discovered_subs = self._collect_subdomains(session)
        new_tasks: List[Task] = []

        if discovered_subs:
            for cap in ("http.headers", "recon.takeover"):
                if cap in capabilities and cap in existing:
                    # refine the already-run capability with the subdomain list
                    new_tasks.append(Task(
                        phase=_PHASE_BY_CAP.get(cap, Phase.ANALYSIS),
                        capability=cap,
                        description=f"Refine {cap} with {len(discovered_subs)} subdomains",
                        params={"subdomains": discovered_subs[:50]},
                    ))

        budget = max_tasks - len(session.tasks)
        return new_tasks[:max(0, budget)]

    @staticmethod
    def _collect_subdomains(session: EngagementSession) -> List[Dict]:
        for task in session.tasks:
            if task.capability == "recon.subdomains" and task.result:
                subs = task.result.get("subdomains")
                if subs:
                    return subs
        return []
