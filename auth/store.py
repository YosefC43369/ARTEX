"""
auth.store
==========

Persistent authentication + API-key store for ARTEX.

Design
------
* **Single-admin bootstrap.** The first account created (only possible while no
  users exist) is the admin. After that, account creation requires an existing
  admin — enforced at the route layer via ``admin_required``.
* **Passwords** are stored only as salted hashes (werkzeug PBKDF2).
* **API keys** gate the AI Agent panel. A key is created by the admin with a
  lifespan: ``valid_days`` (default 30) or ``lifetime`` (never expires), and an
  optional ``single_use`` flag. The plaintext value is stored (admin-only
  visibility, as requested) AND a hash is kept for constant-time verification.
  Key endpoints are admin-only, so non-admins never see keys.
* All state is one JSON file under ``data/`` with atomic writes and a lock.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from werkzeug.security import check_password_hash, generate_password_hash


class PasswordPolicyError(Exception):
    pass


_DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "auth.json")

MIN_PASSWORD_LEN = 8
KEY_PREFIX = "ARTEX-"


def _now() -> float:
    return time.time()


def _key_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class AuthStore:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.environ.get("ARTEX_AUTH_FILE", _DEFAULT_PATH)
        self._lock = threading.Lock()
        self._data: Dict[str, Any] = {"users": {}, "keys": {}, "secret": ""}
        self._load()

    # ── persistence ──────────────────────────────────────────────────────────
    def _load(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if os.path.isfile(self.path):
            try:
                with open(self.path, encoding="utf-8") as fh:
                    self._data = json.load(fh)
            except (OSError, json.JSONDecodeError):
                self._data = {"users": {}, "keys": {}, "secret": ""}
        self._data.setdefault("users", {})
        self._data.setdefault("keys", {})
        if not self._data.get("secret"):
            self._data["secret"] = secrets.token_hex(32)
            self._save()

    def _save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)   # restrict the secrets file
        except OSError:
            pass

    # ── session secret ───────────────────────────────────────────────────────
    def secret_key(self) -> str:
        return self._data["secret"]

    # ── users ────────────────────────────────────────────────────────────────
    def has_users(self) -> bool:
        return bool(self._data["users"])

    def user_count(self) -> int:
        return len(self._data["users"])

    def create_user(self, username: str, password: str, role: str = "user",
                    created_by: Optional[str] = None) -> Dict[str, Any]:
        username = (username or "").strip().lower()
        if not username or not username.isascii() or len(username) < 3:
            raise PasswordPolicyError("Username must be at least 3 ASCII characters.")
        if len(password or "") < MIN_PASSWORD_LEN:
            raise PasswordPolicyError(
                f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        with self._lock:
            if username in self._data["users"]:
                raise PasswordPolicyError("Username already exists.")
            # The very first user is always the admin (bootstrap).
            effective_role = "admin" if not self._data["users"] else role
            record = {
                "username": username,
                "password_hash": generate_password_hash(password),
                "role": effective_role,
                "created_at": _now(),
                "created_by": created_by,
            }
            self._data["users"][username] = record
            self._save()
        return {"username": username, "role": effective_role}

    def verify_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        username = (username or "").strip().lower()
        user = self._data["users"].get(username)
        if not user:
            return None
        if not check_password_hash(user["password_hash"], password or ""):
            return None
        return {"username": username, "role": user["role"]}

    def list_users(self) -> List[Dict[str, Any]]:
        return [{"username": u["username"], "role": u["role"],
                 "created_at": u["created_at"]}
                for u in self._data["users"].values()]

    def set_password(self, username: str, new_password: str) -> bool:
        username = (username or "").strip().lower()
        if len(new_password or "") < MIN_PASSWORD_LEN:
            raise PasswordPolicyError(
                f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        with self._lock:
            user = self._data["users"].get(username)
            if not user:
                return False
            user["password_hash"] = generate_password_hash(new_password)
            self._save()
        return True

    # ── API keys ─────────────────────────────────────────────────────────────
    def create_key(self, label: str = "", valid_days: int = 30,
                   lifetime: bool = False, single_use: bool = False,
                   created_by: Optional[str] = None) -> Dict[str, Any]:
        value = KEY_PREFIX + secrets.token_urlsafe(32)
        key_id = "key_" + secrets.token_hex(6)
        expires_at = None if lifetime else _now() + max(1, int(valid_days)) * 86400
        record = {
            "key_id": key_id,
            "value": value,                 # admin-only visibility (see list_keys)
            "value_hash": _key_hash(value),
            "label": label or "unnamed",
            "created_by": created_by,
            "created_at": _now(),
            "expires_at": expires_at,
            "lifetime": bool(lifetime),
            "single_use": bool(single_use),
            "max_uses": 1 if single_use else None,
            "uses": 0,
            "last_used": None,
            "revoked": False,
        }
        with self._lock:
            self._data["keys"][key_id] = record
            self._save()
        return dict(record)                 # includes plaintext value once

    def verify_key(self, value: str) -> Tuple[bool, str]:
        """Validate a presented key and record a use. Returns (ok, reason)."""
        if not value:
            return False, "no key provided"
        vhash = _key_hash(value)
        with self._lock:
            match = None
            for rec in self._data["keys"].values():
                if hmac.compare_digest(rec.get("value_hash", ""), vhash):
                    match = rec
                    break
            if match is None:
                return False, "invalid key"
            if match["revoked"]:
                return False, "key revoked"
            if match["expires_at"] is not None and _now() > match["expires_at"]:
                return False, "key expired"
            if match["max_uses"] is not None and match["uses"] >= match["max_uses"]:
                return False, "key use limit reached"
            match["uses"] += 1
            match["last_used"] = _now()
            self._save()
            return True, match["key_id"]

    def list_keys(self, include_value: bool = True) -> List[Dict[str, Any]]:
        """Admin-only key listing. include_value reveals the plaintext key."""
        out = []
        for rec in self._data["keys"].values():
            item = {
                "key_id": rec["key_id"], "label": rec["label"],
                "created_at": rec["created_at"], "expires_at": rec["expires_at"],
                "lifetime": rec["lifetime"], "single_use": rec["single_use"],
                "uses": rec["uses"], "max_uses": rec["max_uses"],
                "last_used": rec["last_used"], "revoked": rec["revoked"],
                "status": self._key_status(rec),
            }
            if include_value:
                item["value"] = rec["value"]
            out.append(item)
        out.sort(key=lambda x: x["created_at"], reverse=True)
        return out

    @staticmethod
    def _key_status(rec: Dict[str, Any]) -> str:
        if rec["revoked"]:
            return "revoked"
        if rec["expires_at"] is not None and _now() > rec["expires_at"]:
            return "expired"
        if rec["max_uses"] is not None and rec["uses"] >= rec["max_uses"]:
            return "used"
        return "active"

    def revoke_key(self, key_id: str) -> bool:
        with self._lock:
            rec = self._data["keys"].get(key_id)
            if not rec:
                return False
            rec["revoked"] = True
            self._save()
        return True
