"""
penetration_testing.exceptions
===============================

A single, consistent exception hierarchy for the whole subsystem.

Design rules enforced here:

* Every subsystem error derives from :class:`PenTestError`, so callers (and
  ``app.py``) can catch the whole subsystem with one ``except``.
* Security-policy denials (:class:`ScopeViolation`, :class:`PermissionDenied`)
  carry ``retryable = False``. The executor and orchestrator must never retry
  these as if they were transient faults — doing so would be an attempt to
  brute-force past a safety control.
* Transient faults (:class:`LLMError`, :class:`ToolExecutionError`,
  :class:`NetworkError`) default to ``retryable = True`` so bounded retry logic
  can act on them.
"""

from __future__ import annotations

from typing import Optional


class PenTestError(Exception):
    """Base class for every error raised by the subsystem."""

    retryable: bool = False

    def __init__(self, message: str, *, detail: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.detail = detail

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.detail:
            return f"{self.message} ({self.detail})"
        return self.message


# ── Configuration ────────────────────────────────────────────────────────────
class ConfigurationError(PenTestError):
    """config.xml missing, malformed, or failing validation. Fails closed."""


# ── Security policy (never retryable) ────────────────────────────────────────
class SecurityPolicyError(PenTestError):
    retryable = False


class ScopeViolation(SecurityPolicyError):
    """A target / URL / IP / port / path fell outside the authorized scope."""


class PermissionDenied(SecurityPolicyError):
    """A capability was requested that the target's permissions do not grant."""


class RateLimitExceeded(SecurityPolicyError):
    """The configured request-rate budget for the engagement was exhausted."""


# ── Integration ──────────────────────────────────────────────────────────────
class IntegrationError(PenTestError):
    """A failure wiring to, discovering, or adapting an existing module."""


class ModuleNotRegistered(IntegrationError):
    """An operation referenced a capability that is not in the registry."""


# ── Execution (retryable by default) ─────────────────────────────────────────
class ExecutionError(PenTestError):
    retryable = True


class ToolExecutionError(ExecutionError):
    """A registered tool/module raised while running."""


class ExecutionTimeout(ExecutionError):
    """A task exceeded its allotted wall-clock budget."""


class ExecutionCancelled(PenTestError):
    """The engagement was cancelled cooperatively; not an error condition."""

    retryable = False


# ── External services ────────────────────────────────────────────────────────
class LLMError(PenTestError):
    """OpenRouter call failed or returned an unusable response."""

    retryable = True


class NetworkError(ExecutionError):
    """Low-level network failure during a delegated operation."""


# ── Persistence / serialization ──────────────────────────────────────────────
class StorageError(PenTestError):
    """Evidence/session persistence failure."""


class SerializationError(PenTestError):
    """A model could not be serialized/deserialized."""
