"""ARTEX authentication & access-control subsystem.

Provides:
* Account management (admin-created users, password-hashed).
* An admin-only API-key system that gates the AI Agent panel. Keys have a
  configurable lifespan (default 30 days, or lifetime) and optional single-use.
* A stable Flask session secret (persisted, fixing per-restart session loss).

All state lives in a local JSON file under ``data/`` (gitignored).
"""

from .store import AuthStore, PasswordPolicyError

__all__ = ["AuthStore", "PasswordPolicyError"]
