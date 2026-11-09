"""
Tests for the people / entity intelligence layer.

Every test runs offline: the collector and the username HTTP checker are
stubbed, so no network I/O occurs. The suite asserts the engine's scope
enforcement, provenance tagging and — above all — its data-minimisation
guarantees (secrets stripped, PII redacted, breach data kept as metadata only).
"""

import pytest

from penetration_testing.constants import ValidationStatus
from penetration_testing.intelligence.osint import (
    EntityType,
    Observation,
    OsintEntity,
    OsintGraph,
    Provenance,
)
from penetration_testing.intelligence.people_osint import (
    PeopleIntelligenceEngine,
    PhoneIntel,
    UsernameEnumerator,
    _strip_secrets,
)


class StubPeopleCollector:
    def __init__(self, payload=None):
        self.payload = payload
        self.calls = []

    def collect(self, target, scope=None, deep=False):
        self.calls.append((target, deep))
        if self.payload is not None:
            return self.payload
        return {
            "organization": {"name": "Example Corp", "domain": "example.com"},
            "people": [
                {
                    "name": "Alice Example", "role": "CISO",
                    "emails": ["alice@example.com"],
                    "phones": ["+66812345678"],
                    "usernames": [
                        {"handle": "alice", "platform": "github",
                         "url": "https://github.com/alice", "exists": True},
                        {"handle": "alice", "platform": "reddit",
                         "url": "https://www.reddit.com/user/alice",
                         "exists": None},
                    ],
                    "profile_urls": ["https://example.com/team/alice"],
                    "source": "company_site",
                    # a sloppy collector leaks a secret — must be stripped:
                    "password": "hunter2",
                },
                {
                    "name": "Bob Outsider", "role": "Nobody",
                    "emails": ["bob@notexample.org"],   # out of scope
                    "source": "random",
                },
            ],
            "breach_exposures": [
                {"email": "alice@example.com", "breach": "AcmeLeak2021",
                 "date": "2021-05-01", "data_classes": ["emails", "passwords"],
                 "source": "breach_index",
                 "password": "SHOULD_NOT_APPEAR"},
            ],
        }


def _engine(payload=None, **kw):
    return PeopleIntelligenceEngine(collector=StubPeopleCollector(payload), **kw)


# ── core ──────────────────────────────────────────────────────────────────────
def test_builds_person_and_affiliation():
    g = _engine().investigate("example.com")
    people = g.of_type(EntityType.PERSON)
    assert {p.value for p in people} == {"Alice Example"}   # Bob dropped
    org = g.of_type(EntityType.ORGANIZATION)[0]
    assert org.attributes["domain"] == "example.com"
    assert any(r.rtype.value == "affiliated_with" for r in g.relationships)


def test_out_of_scope_person_is_dropped_and_counted():
    eng = _engine()
    eng.investigate("example.com")
    assert eng.skipped_out_of_scope == 1
    g = eng.investigate("example.com")
    assert all("Outsider" not in p.value for p in g.of_type(EntityType.PERSON))


def test_custom_scope_predicate():
    eng = PeopleIntelligenceEngine(
        collector=StubPeopleCollector(),
        in_scope=lambda person, target: False,   # drop everyone
    )
    g = eng.investigate("example.com")
    assert g.of_type(EntityType.PERSON) == []


# ── data minimisation ─────────────────────────────────────────────────────────
def test_person_secret_field_is_never_stored():
    g = _engine().investigate("example.com")
    alice = g.get("person:alice example")
    assert "password" not in alice.attributes
    assert "hunter2" not in str(alice.to_dict())


def test_email_is_redacted_in_output():
    g = _engine().investigate("example.com")
    nodes = g.to_graph_dict(redact=True)["nodes"]
    emails = [n for n in nodes if n["type"] == "email"]
    assert emails
    assert all("alice@example.com" not in n["value"] for n in emails)
    assert all(n["value"].endswith("@example.com") for n in emails)


def test_phone_is_redacted_but_metadata_kept():
    g = _engine().investigate("example.com")
    phone = g.of_type(EntityType.PHONE)[0]
    assert phone.attributes["country"] == "Thailand"
    assert phone.attributes["country_code"] == "66"
    rendered = phone.display_value(redact=True)
    assert rendered.startswith("+66")
    assert "812345678" not in rendered      # middle masked
    assert rendered.endswith("78")


def test_breach_is_metadata_only():
    g = _engine().investigate("example.com")
    breach = g.of_type(EntityType.BREACH)[0]
    serialized = str(breach.to_dict())
    assert "SHOULD_NOT_APPEAR" not in serialized
    assert breach.attributes["data_classes"] == ["emails", "passwords"]
    assert breach.validation_status == ValidationStatus.POTENTIAL
    # email -> breach edge exists
    assert any(r.rtype.value == "appears_in_breach" for r in g.relationships)


def test_strip_secrets_helper():
    cleaned = _strip_secrets({"name": "x", "password": "p", "TOKEN": "t",
                              "role": "admin"})
    assert cleaned == {"name": "x", "role": "admin"}


# ── username / social profiles ────────────────────────────────────────────────
def test_verified_profile_is_observed_unverified_is_inferred():
    g = _engine().investigate("example.com")
    profiles = {p.attributes["platform"]: p
                for p in g.of_type(EntityType.SOCIAL_PROFILE)}
    assert profiles["github"].provenance[0].observation == Observation.THIRD_PARTY
    assert profiles["github"].attributes["verified_public"] is True
    # reddit had exists=None -> inferred, not dropped
    assert profiles["reddit"].provenance[0].observation == Observation.INFERRED
    assert profiles["reddit"].attributes["verified_public"] is False


def test_username_nodes_created():
    g = _engine().investigate("example.com")
    assert any(u.value == "alice" for u in g.of_type(EntityType.USERNAME))


# ── merge into an existing (infrastructure) graph ─────────────────────────────
def test_people_merge_into_existing_graph():
    g = OsintGraph()
    g.upsert_entity(OsintEntity(EntityType.DOMAIN, "example.com",
                                provenance=[Provenance("artex")]))
    before = len(g.entities)
    _engine().investigate("example.com", graph=g)
    assert len(g.entities) > before
    assert g.get("domain:example.com") is not None       # infra node preserved
    assert g.of_type(EntityType.PERSON)                  # people added alongside


# ── PhoneIntel ────────────────────────────────────────────────────────────────
def test_phone_parse_variants():
    assert PhoneIntel.parse("+66 81 234 5678").country == "Thailand"
    assert PhoneIntel.parse("0066812345678").country == "Thailand"  # 00 prefix
    assert PhoneIntel.parse("+1 415 555 0100").country_code == "1"
    assert PhoneIntel.parse("12345") is None               # too short
    assert PhoneIntel.parse("") is None
    local = PhoneIntel.parse("0812345678")                 # no country code
    assert local is not None and local.country == "unknown"


# ── UsernameEnumerator ────────────────────────────────────────────────────────
def test_username_enumerator_with_stub_checker():
    seen = []

    def checker(url):
        seen.append(url)
        return "alice" in url and "github" in url  # exists only on github

    enum = UsernameEnumerator(checker=checker, sleeper=lambda s: None)
    hits = {h.platform: h.exists for h in enum.enumerate("alice")}
    assert hits["github"] is True
    assert hits["reddit"] is False
    assert len(seen) == len(enum.platforms)


def test_username_enumerator_rejects_bad_handle():
    enum = UsernameEnumerator(checker=lambda u: True)
    assert enum.enumerate("has spaces!") == []
    assert enum.enumerate("") == []


def test_username_enumerator_injected_checker_does_not_sleep():
    calls = []
    enum = UsernameEnumerator(checker=lambda u: None,
                              sleeper=lambda s: calls.append(s))
    enum.enumerate("alice")
    assert calls == []   # throttle only applies to the live default checker


# ── guards ────────────────────────────────────────────────────────────────────
def test_requires_collector_and_target():
    with pytest.raises(ValueError):
        PeopleIntelligenceEngine(collector=None).investigate("example.com")
    with pytest.raises(ValueError):
        _engine().investigate("")
