"""
ARTEX Autonomous Penetration-Testing Subsystem
==============================================

An integrated, scope-enforced, non-destructive autonomous assessment subsystem
that reuses ARTEX's existing reconnaissance/scanning modules through a
controlled bridge and the existing OpenRouter (``OPENROUTER_API_KEY``)
convention.

Public entry point
------------------
>>> from penetration_testing import PenetrationTestingAgent
>>> agent = PenetrationTestingAgent()            # loads config.xml (fail-closed)
>>> agent.start_engagement("example-target")

See ``penetration_testing/agent.py`` for the full API and ``config.xml`` for
scope configuration.
"""

from __future__ import annotations

from .constants import SUBSYSTEM_NAME, SUBSYSTEM_VERSION
from .exceptions import (
    ConfigurationError,
    PenTestError,
    PermissionDenied,
    ScopeViolation,
)

__version__ = SUBSYSTEM_VERSION
__all__ = [
    "PenetrationTestingAgent",
    "SUBSYSTEM_NAME",
    "SUBSYSTEM_VERSION",
    "PenTestError",
    "ConfigurationError",
    "ScopeViolation",
    "PermissionDenied",
    "__version__",
]


def __getattr__(name: str):
    # Lazy import of the agent so that importing the package (e.g. for constants)
    # does not pull the full component graph until actually needed.
    if name == "PenetrationTestingAgent":
        from .agent import PenetrationTestingAgent
        return PenetrationTestingAgent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
