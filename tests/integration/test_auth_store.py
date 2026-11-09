import time

import pytest

from auth.store import AuthStore, PasswordPolicyError


@pytest.fixture
def store(tmp_path):
    return AuthStore(path=str(tmp_path / "auth.json"))


# ── users ────────────────────────────────────────────────────────────────────
def test_first_user_is_admin(store):
    assert store.has_users() is False
    u = store.create_user("boss", "password1")
    assert u["role"] == "admin"            # first user forced to admin
    # subsequent users honor requested role
    u2 = store.create_user("analyst", "password2", role="user")
    assert u2["role"] == "user"


def test_password_policy_and_duplicates(store):
    with pytest.raises(PasswordPolicyError):
        store.create_user("ab", "password1")        # username too short
    with pytest.raises(PasswordPolicyError):
        store.create_user("validuser", "short")     # password too short
    store.create_user("dup", "password1")
    with pytest.raises(PasswordPolicyError):
        store.create_user("dup", "password2")        # duplicate


def test_verify_user(store):
    store.create_user("boss", "password1")
    assert store.verify_user("boss", "password1")["role"] == "admin"
    assert store.verify_user("boss", "wrong") is None
    assert store.verify_user("nobody", "password1") is None


def test_secret_is_stable(tmp_path):
    p = str(tmp_path / "auth.json")
    s1 = AuthStore(path=p).secret_key()
    s2 = AuthStore(path=p).secret_key()       # reload from disk
    assert s1 == s2 and len(s1) >= 32


# ── keys ─────────────────────────────────────────────────────────────────────
def test_key_default_30_days(store):
    key = store.create_key(label="k", created_by="boss")
    assert key["value"].startswith("ARTEX-")
    # ~30 days in the future
    assert 29 * 86400 < (key["expires_at"] - time.time()) <= 30 * 86400
    ok, _ = store.verify_key(key["value"])
    assert ok is True


def test_lifetime_key_never_expires(store):
    key = store.create_key(lifetime=True)
    assert key["expires_at"] is None
    ok, _ = store.verify_key(key["value"])
    assert ok


def test_single_use_key(store):
    key = store.create_key(single_use=True)
    assert store.verify_key(key["value"])[0] is True
    ok, reason = store.verify_key(key["value"])      # second use
    assert ok is False and "limit" in reason


def test_expired_key_rejected(store):
    key = store.create_key(valid_days=1)
    # force expiry in the stored record
    store._data["keys"][key["key_id"]]["expires_at"] = time.time() - 10
    ok, reason = store.verify_key(key["value"])
    assert ok is False and reason == "key expired"


def test_revoke_key(store):
    key = store.create_key()
    assert store.revoke_key(key["key_id"]) is True
    ok, reason = store.verify_key(key["value"])
    assert ok is False and reason == "key revoked"


def test_invalid_key_rejected(store):
    assert store.verify_key("ARTEX-nope")[0] is False
    assert store.verify_key("")[0] is False


def test_list_keys_admin_sees_value(store):
    store.create_key(label="visible")
    listed = store.list_keys(include_value=True)
    assert listed and "value" in listed[0]
    # non-value listing hides the secret
    hidden = store.list_keys(include_value=False)
    assert "value" not in hidden[0]
