"""
Tests for the OSINT unification layer.

All tests run offline: the collector is stubbed, so no network I/O occurs and
the suite asserts the engine's *normalisation* behaviour, not any provider.
"""

from penetration_testing.constants import Confidence, ValidationStatus
from penetration_testing.intelligence.osint import (
    EntityType,
    Observation,
    OsintEntity,
    OsintGraph,
    OsintIntelligenceEngine,
    Provenance,
    RelationType,
)


class StubCorrelator:
    """Returns a representative AIOSINTCorrelator.correlate() payload."""

    def __init__(self, payload=None):
        self.payload = payload
        self.calls = []

    def correlate(self, domain, scan_results=None, deep=False):
        self.calls.append((domain, deep))
        if self.payload is not None:
            return self.payload
        return {
            "infrastructure": {
                "asn": "AS13335", "asn_org": "Cloudflare",
                "ips": [{"ip": "203.0.113.10", "cloud": "cloudflare"}],
            },
            "subdomains": [
                {"subdomain": "api.example.com", "sources": ["crt.sh", "otx"]},
                {"subdomain": "mail.example.com", "sources": ["securitytrails"]},
                {"subdomain": "evil.notexample.com", "sources": ["otx"]},  # out of scope
            ],
            "emails": {"addresses": [{"email": "admin@example.com"}]},
            "exposed_paths": [
                {"url": "https://example.com/old/login", "source": "wayback"},
            ],
            "tech_signals": [{"name": "nginx/1.18.0"}],
            "certificates": [{"serial": "AABBCC", "common_name": "example.com"}],
            "dns_intelligence": {
                "spf": "v=spf1 -all",
                "nameservers": [{"host": "ns1.example.com"}],
                "mail_servers": [{"host": "mx.example.com"}],
            },
            "credential_leaks": [
                {"url": "https://github.com/x/y/blob/z/.env",
                 "indicator": "aws_key_pattern", "secret": "AKIA_SHOULD_NOT_APPEAR"},
            ],
        }


def _engine(payload=None):
    return OsintIntelligenceEngine(correlator=StubCorrelator(payload))


# ── core normalisation ───────────────────────────────────────────────────────
def test_investigate_builds_entities_and_relationships():
    g = _engine().investigate("example.com")
    assert g.get("domain:example.com").validation_status == ValidationStatus.CONFIRMED
    assert {e.value for e in g.of_type(EntityType.SUBDOMAIN)} == {
        "api.example.com", "mail.example.com"}          # out-of-scope dropped
    assert any(e.value == "203.0.113.10" for e in g.of_type(EntityType.IP))
    assert any(e.value == "AS13335" for e in g.of_type(EntityType.ASN))
    assert g.relationships, "expected relationships to be created"


def test_out_of_scope_hostnames_are_dropped():
    g = _engine().investigate("example.com")
    assert all("notexample.com" not in e.value
               for e in g.of_type(EntityType.SUBDOMAIN))


def test_custom_scope_predicate_is_honoured():
    eng = OsintIntelligenceEngine(
        correlator=StubCorrelator(),
        in_scope=lambda host: host == "example.com",  # nothing but the root
    )
    g = eng.investigate("example.com")
    assert g.of_type(EntityType.SUBDOMAIN) == []       # all subs filtered out


# ── provenance / integrity ───────────────────────────────────────────────────
def test_every_entity_carries_provenance():
    g = _engine().investigate("example.com")
    for e in g.entities:
        assert e.provenance, f"{e.id} has no provenance"
        for p in e.provenance:
            assert p.source and p.collected_at


def test_tech_fingerprint_is_inferred_not_confirmed():
    g = _engine().investigate("example.com")
    tech = g.of_type(EntityType.TECHNOLOGY)[0]
    assert tech.validation_status == ValidationStatus.POTENTIAL
    assert tech.provenance[0].observation == Observation.INFERRED


def test_multiple_sources_merge_into_one_entity():
    g = _engine().investigate("example.com")
    api = g.get("subdomain:api.example.com")
    assert set(api.sources) == {"crt.sh", "otx"}       # not duplicated as 2 nodes


def test_wayback_path_tagged_historical():
    g = _engine().investigate("example.com")
    path = g.of_type(EntityType.URL_PATH)[0]
    assert path.provenance[0].observation == Observation.HISTORICAL


# ── data minimisation ────────────────────────────────────────────────────────
def test_emails_are_redacted_in_output():
    g = _engine().investigate("example.com")
    nodes = g.to_graph_dict(redact=True)["nodes"]
    emails = [n for n in nodes if n["type"] == "email"]
    assert emails and "admin@example.com" not in emails[0]["value"]
    assert emails[0]["value"].endswith("@example.com")


def test_credential_leak_never_stores_the_secret():
    g = _engine().investigate("example.com")
    leak = g.of_type(EntityType.CREDENTIAL_LEAK)[0]
    serialized = str(leak.to_dict())
    assert "AKIA_SHOULD_NOT_APPEAR" not in serialized
    assert leak.attributes["indicator"] == "aws_key_pattern"
    assert leak.validation_status == ValidationStatus.POTENTIAL


# ── graph mechanics ──────────────────────────────────────────────────────────
def test_graph_dedups_entities_and_merges_provenance():
    g = OsintGraph()
    g.upsert_entity(OsintEntity(EntityType.IP, "1.2.3.4",
                                provenance=[Provenance("a")]))
    g.upsert_entity(OsintEntity(EntityType.IP, "1.2.3.4",
                                provenance=[Provenance("b")]))
    assert len(g.of_type(EntityType.IP)) == 1
    assert set(g.get("ip:1.2.3.4").sources) == {"a", "b"}


def test_link_rejects_dangling_edges():
    g = OsintGraph()
    g.upsert_entity(OsintEntity(EntityType.DOMAIN, "example.com",
                                provenance=[Provenance("x")]))
    rel = g.link(RelationType.RESOLVES_TO, "domain:example.com",
                 "ip:9.9.9.9", Provenance("x"))
    assert rel is None                                  # target not in graph


def test_summary_and_graph_dict_shapes():
    g = _engine().investigate("example.com")
    summary = g.to_summary()
    assert summary["total_entities"] >= 6
    assert "api.example.com" in summary["subdomains"]
    assert summary["credential_leak_indicators"] == 1
    gd = g.to_graph_dict()
    assert {"nodes", "edges"} == set(gd)
    assert all({"id", "type", "value", "sources"} <= set(n) for n in gd["nodes"])


def test_empty_profile_yields_only_root():
    g = _engine(payload={}).investigate("example.com")
    assert len(g.entities) == 1
    assert g.entities[0].etype == EntityType.DOMAIN


def test_best_confidence_picks_highest():
    e = OsintEntity(EntityType.IP, "1.1.1.1", provenance=[
        Provenance("a", confidence=Confidence.LOW),
        Provenance("b", confidence=Confidence.HIGH),
    ])
    assert e.best_confidence() == Confidence.HIGH
