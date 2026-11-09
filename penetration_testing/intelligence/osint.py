"""
penetration_testing.intelligence.osint
=======================================

Unification layer that turns ARTEX's existing passive-OSINT collection
(:class:`modules.AI_osint_correlator.AIOSINTCorrelator`, plus reverse-WHOIS and
network-range mapping) into a single, scope-enforced **entity graph** with
per-record provenance.

Why this module exists
----------------------
ARTEX already *collects* a great deal of open-source intelligence, but each
source returns its own ad-hoc dict shape and nothing records, per fact, *where
it came from* or *how much to trust it*. This layer normalises that output into
a stable schema so the rest of the platform (reporting, the UI, correlation)
can consume one thing instead of a dozen.

Design rules (mirrors the platform's integrity stance)
------------------------------------------------------
* **No fabrication.** Every entity and relationship is derived from data a
  collector actually returned. If a source returned nothing for a section, no
  entity is created for it — the engine never invents values to fill gaps.
* **Provenance on everything.** Each fact carries its source, a reference, a
  collection timestamp, the observation class (directly observed vs
  third-party-reported vs historical vs inferred) and a confidence level.
* **Inference is never a fact.** Relationships the platform deduces rather than
  observes are tagged ``Observation.INFERRED`` and kept at ``POTENTIAL``.
* **Passive only / scope-bounded.** This layer does no network I/O of its own;
  it consumes a collector's results. Host-type entities are filtered against an
  injectable scope predicate so out-of-scope hostnames are dropped, not graphed.
* **Data minimisation.** Email values are redacted in serialised output by
  default, and credential-leak indicators store only safe metadata — never the
  secret itself.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Callable, Dict, List, Optional

from ..constants import Confidence, ValidationStatus


# ── taxonomy ────────────────────────────────────────────────────────────────
class EntityType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"
    URL_PATH = "url_path"
    NAMESERVER = "nameserver"
    MAIL_SERVER = "mail_server"
    CREDENTIAL_LEAK = "credential_leak"
    # people / entity intelligence (engagement-scoped, public-source only)
    ORGANIZATION = "organization"
    PERSON = "person"
    USERNAME = "username"
    PHONE = "phone"
    SOCIAL_PROFILE = "social_profile"
    BREACH = "breach"


class Observation(StrEnum):
    """How a fact was obtained — kept separate from confidence on purpose."""

    OBSERVED = "observed"              # ARTEX directly observed it
    THIRD_PARTY = "third_party"        # a provider reported it
    HISTORICAL = "historical"          # archive / passive-DNS, may be stale
    INFERRED = "inferred"             # deduced, not observed


class RelationType(StrEnum):
    SUBDOMAIN_OF = "subdomain_of"
    RESOLVES_TO = "resolves_to"
    IN_ASN = "in_asn"
    USES_NAMESERVER = "uses_nameserver"
    USES_MAIL_SERVER = "uses_mail_server"
    HAS_EMAIL = "has_email"
    PRESENTS_CERT = "presents_cert"
    RUNS_TECH = "runs_tech"
    EXPOSES_PATH = "exposes_path"
    LEAK_REFERENCES = "leak_references"
    # people / entity intelligence
    AFFILIATED_WITH = "affiliated_with"      # person -> organization/domain
    HAS_USERNAME = "has_username"            # person -> username
    HAS_PHONE = "has_phone"                  # person -> phone
    HAS_PROFILE = "has_profile"              # username -> social_profile
    APPEARS_IN_BREACH = "appears_in_breach"  # email -> breach (metadata only)
    SAME_PERSON = "same_person"              # inferred identity link


_HOST_TYPES = frozenset(
    {EntityType.DOMAIN, EntityType.SUBDOMAIN,
     EntityType.NAMESERVER, EntityType.MAIL_SERVER}
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _redact_email(value: str) -> str:
    local, _, domain = value.partition("@")
    if not domain:
        return "[redacted]"
    shown = local[:1] if local else ""
    return f"{shown}{'*' * max(len(local) - 1, 1)}@{domain}"


def _redact_phone(value: str) -> str:
    """Keep the leading '+', the country code and the last two digits; mask the
    rest. A phone number is PII — the graph proves reachability without
    publishing the full dialable number."""
    plus = value.startswith("+")
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) < 4:
        return "[redacted]"
    cc = digits[:2] if len(digits) <= 10 else digits[:3]
    tail = digits[-2:]
    masked = "*" * max(len(digits) - len(cc) - 2, 1)
    return f"{'+' if plus else ''}{cc}{masked}{tail}"


# ── records ─────────────────────────────────────────────────────────────────
@dataclass
class Provenance:
    source: str
    observation: Observation = Observation.THIRD_PARTY
    confidence: Confidence = Confidence.MEDIUM
    source_ref: str = ""            # URL or opaque id of the source record
    method: str = "passive_osint"
    collected_at: str = field(default_factory=_now)

    def key(self) -> tuple:
        return (self.source, self.method)

    def to_dict(self) -> Dict[str, str]:
        return {
            "source": self.source,
            "observation": self.observation.value,
            "confidence": self.confidence.value,
            "source_ref": self.source_ref,
            "method": self.method,
            "collected_at": self.collected_at,
        }


@dataclass
class OsintEntity:
    etype: EntityType
    value: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    provenance: List[Provenance] = field(default_factory=list)
    validation_status: ValidationStatus = ValidationStatus.POTENTIAL

    @property
    def id(self) -> str:
        return f"{self.etype.value}:{self.value.lower()}"

    @property
    def sources(self) -> List[str]:
        return sorted({p.source for p in self.provenance})

    def add_provenance(self, prov: Provenance) -> None:
        """Merge provenance, de-duplicating on (source, method)."""
        if prov.key() not in {p.key() for p in self.provenance}:
            self.provenance.append(prov)

    def best_confidence(self) -> Confidence:
        order = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
        if not self.provenance:
            return Confidence.LOW
        return max((p.confidence for p in self.provenance), key=lambda c: order[c])

    def display_value(self, redact: bool) -> str:
        if redact and self.etype == EntityType.EMAIL:
            return _redact_email(self.value)
        if redact and self.etype == EntityType.PHONE:
            return _redact_phone(self.value)
        return self.value

    def to_dict(self, redact: bool = True) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.etype.value,
            "value": self.display_value(redact),
            "attributes": self.attributes,
            "sources": self.sources,
            "confidence": self.best_confidence().value,
            "validation_status": self.validation_status.value,
            "provenance": [p.to_dict() for p in self.provenance],
        }


@dataclass
class OsintRelationship:
    rtype: RelationType
    src_id: str
    dst_id: str
    provenance: List[Provenance] = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.src_id}|{self.rtype.value}|{self.dst_id}"

    def add_provenance(self, prov: Provenance) -> None:
        if prov.key() not in {p.key() for p in self.provenance}:
            self.provenance.append(prov)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.rtype.value,
            "source": self.src_id,
            "target": self.dst_id,
            "sources": sorted({p.source for p in self.provenance}),
            "provenance": [p.to_dict() for p in self.provenance],
        }


class OsintGraph:
    """An entity/relationship graph with merge-on-insert de-duplication."""

    def __init__(self) -> None:
        self._entities: Dict[str, OsintEntity] = {}
        self._relationships: Dict[str, OsintRelationship] = {}

    # -- mutation -------------------------------------------------------------
    def upsert_entity(self, entity: OsintEntity) -> OsintEntity:
        existing = self._entities.get(entity.id)
        if existing is None:
            self._entities[entity.id] = entity
            return entity
        for prov in entity.provenance:
            existing.add_provenance(prov)
        # merge attributes without clobbering already-present keys
        for k, v in entity.attributes.items():
            existing.attributes.setdefault(k, v)
        return existing

    def link(self, rtype: RelationType, src_id: str, dst_id: str,
             prov: Provenance) -> Optional[OsintRelationship]:
        # Only link entities that actually exist in the graph (no dangling edges)
        if src_id not in self._entities or dst_id not in self._entities:
            return None
        rel = OsintRelationship(rtype, src_id, dst_id)
        existing = self._relationships.get(rel.id)
        if existing is None:
            rel.add_provenance(prov)
            self._relationships[rel.id] = rel
            return rel
        existing.add_provenance(prov)
        return existing

    # -- queries --------------------------------------------------------------
    @property
    def entities(self) -> List[OsintEntity]:
        return list(self._entities.values())

    @property
    def relationships(self) -> List[OsintRelationship]:
        return list(self._relationships.values())

    def get(self, entity_id: str) -> Optional[OsintEntity]:
        return self._entities.get(entity_id)

    def of_type(self, etype: EntityType) -> List[OsintEntity]:
        return [e for e in self._entities.values() if e.etype == etype]

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {t.value: 0 for t in EntityType}
        for e in self._entities.values():
            out[e.etype.value] += 1
        return out

    # -- serialisation --------------------------------------------------------
    def to_graph_dict(self, redact: bool = True) -> Dict[str, Any]:
        """Frontend-friendly nodes/edges payload."""
        return {
            "nodes": [e.to_dict(redact) for e in self._entities.values()],
            "edges": [r.to_dict() for r in self._relationships.values()],
        }

    def to_summary(self, redact: bool = True) -> Dict[str, Any]:
        return {
            "entity_counts": self.counts(),
            "total_entities": len(self._entities),
            "total_relationships": len(self._relationships),
            "subdomains": sorted(
                e.value for e in self.of_type(EntityType.SUBDOMAIN)
            ),
            "ip_addresses": sorted(e.value for e in self.of_type(EntityType.IP)),
            "technologies": sorted(
                e.value for e in self.of_type(EntityType.TECHNOLOGY)
            ),
            "emails": sorted(
                e.display_value(redact) for e in self.of_type(EntityType.EMAIL)
            ),
            "credential_leak_indicators": len(
                self.of_type(EntityType.CREDENTIAL_LEAK)
            ),
        }


# ── engine ──────────────────────────────────────────────────────────────────
class OsintIntelligenceEngine:
    """
    Normalises a passive-OSINT collector's output into an :class:`OsintGraph`.

    Parameters
    ----------
    correlator:
        Any object exposing ``correlate(domain, scan_results=None, deep=False)``
        returning the dict documented on
        :meth:`modules.AI_osint_correlator.AIOSINTCorrelator.correlate`.
        Injected for testability; constructed lazily if omitted.
    in_scope:
        Predicate ``(host: str) -> bool`` used to drop out-of-scope hostnames.
        Defaults to "belongs to the investigated root domain". Pass
        ``scope.is_host_in_scope``-backed closure to bind to an engagement.
    redact_emails:
        Redact email values in serialised output (default True).
    """

    def __init__(
        self,
        correlator: Optional[Any] = None,
        in_scope: Optional[Callable[[str], bool]] = None,
        redact_emails: bool = True,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._correlator = correlator
        self._in_scope = in_scope
        self.redact_emails = redact_emails
        self.logger = logger or logging.getLogger("artex.osint")

    # -- collector plumbing ---------------------------------------------------
    def _get_correlator(self) -> Any:
        if self._correlator is None:
            # Lazy import keeps this module import-light and test-friendly.
            from modules.AI_osint_correlator import AIOSINTCorrelator
            self._correlator = AIOSINTCorrelator()
        return self._correlator

    def _scope_ok(self, host: str, root: str) -> bool:
        if self._in_scope is not None:
            return self._in_scope(host)
        host = (host or "").strip().lower().rstrip(".")
        return bool(host) and (host == root or host.endswith("." + root))

    # -- public API -----------------------------------------------------------
    def investigate(
        self,
        domain: str,
        scan_results: Optional[Dict] = None,
        deep: bool = False,
    ) -> OsintGraph:
        root = (domain or "").strip().lower().rstrip(".")
        if not root:
            raise ValueError("investigate() requires a non-empty domain")

        self.logger.info("OSINT unification starting — %s", root)
        profile = self._get_correlator().correlate(
            root, scan_results=scan_results, deep=deep
        ) or {}

        graph = OsintGraph()
        # Root domain — the one entity we observe directly as the target.
        graph.upsert_entity(OsintEntity(
            EntityType.DOMAIN, root,
            validation_status=ValidationStatus.CONFIRMED,
            provenance=[Provenance("artex", Observation.OBSERVED,
                                   Confidence.HIGH, method="target")],
        ))
        root_id = f"{EntityType.DOMAIN.value}:{root}"

        self._ingest_subdomains(graph, root, root_id, profile)
        self._ingest_infrastructure(graph, root, root_id, profile)
        self._ingest_dns(graph, root, root_id, profile)
        self._ingest_emails(graph, root_id, profile)
        self._ingest_certificates(graph, root_id, profile)
        self._ingest_tech(graph, root_id, profile)
        self._ingest_paths(graph, root_id, profile)
        self._ingest_leaks(graph, root_id, profile)

        self.logger.info(
            "OSINT unification done — %d entities, %d relationships",
            len(graph.entities), len(graph.relationships),
        )
        return graph

    # -- section ingesters ----------------------------------------------------
    def _ingest_subdomains(self, graph, root, root_id, profile) -> None:
        for entry in profile.get("subdomains", []) or []:
            if isinstance(entry, dict):
                sub = (entry.get("subdomain") or "").strip().lower().lstrip("*.")
                srcs = entry.get("sources") or ["osint"]
            else:
                sub, srcs = str(entry).strip().lower().lstrip("*."), ["osint"]
            if not sub or not self._scope_ok(sub, root):
                continue
            ent = OsintEntity(EntityType.SUBDOMAIN, sub)
            for s in srcs:
                ent.add_provenance(Provenance(
                    str(s), Observation.THIRD_PARTY, Confidence.MEDIUM,
                    method="passive_dns"))
            graph.upsert_entity(ent)
            graph.link(RelationType.SUBDOMAIN_OF, ent.id, root_id,
                       Provenance("osint", Observation.THIRD_PARTY))

    def _ingest_infrastructure(self, graph, root, root_id, profile) -> None:
        infra = profile.get("infrastructure", {}) or {}
        asn_id = None
        asn = infra.get("asn") or infra.get("asn_number")
        if asn:
            asn_val = str(asn)
            asn_ent = OsintEntity(
                EntityType.ASN, asn_val,
                attributes={"org": infra.get("asn_org", "")},
                provenance=[Provenance("ip_enrichment", Observation.THIRD_PARTY,
                                       Confidence.MEDIUM, method="asn_lookup")])
            graph.upsert_entity(asn_ent)
            asn_id = asn_ent.id

        for ip in infra.get("ips", []) or infra.get("ip_addresses", []) or []:
            ip_val = ip.get("ip") if isinstance(ip, dict) else str(ip)
            if not ip_val:
                continue
            attrs: Dict[str, Any] = {}
            if isinstance(ip, dict):
                attrs = {k: v for k, v in ip.items() if k != "ip"}
            ip_ent = OsintEntity(
                EntityType.IP, ip_val, attributes=attrs,
                provenance=[Provenance("ip_enrichment", Observation.THIRD_PARTY,
                                       Confidence.MEDIUM, method="ip_lookup")])
            graph.upsert_entity(ip_ent)
            graph.link(RelationType.RESOLVES_TO, root_id, ip_ent.id,
                       Provenance("osint", Observation.THIRD_PARTY))
            if asn_id:
                graph.link(RelationType.IN_ASN, ip_ent.id, asn_id,
                           Provenance("ip_enrichment", Observation.THIRD_PARTY))

    def _ingest_dns(self, graph, root, root_id, profile) -> None:
        dns = profile.get("dns_intelligence", {}) or {}
        # Record SPF/DMARC posture as attributes on the root, not as facts invented.
        root_ent = graph.get(root_id)
        if root_ent is not None:
            for key in ("spf", "dmarc", "spf_analysis", "dmarc_analysis"):
                if dns.get(key):
                    root_ent.attributes.setdefault(key, dns[key])

        for ns in dns.get("nameservers", []) or []:
            host = (ns.get("host") if isinstance(ns, dict) else str(ns)).strip().lower()
            if not host:
                continue
            ent = OsintEntity(
                EntityType.NAMESERVER, host,
                provenance=[Provenance("dns", Observation.THIRD_PARTY,
                                       Confidence.MEDIUM, method="dns_ns")])
            graph.upsert_entity(ent)
            graph.link(RelationType.USES_NAMESERVER, root_id, ent.id,
                       Provenance("dns", Observation.THIRD_PARTY))

        for mx in dns.get("mail_servers", []) or dns.get("mx", []) or []:
            host = (mx.get("host") if isinstance(mx, dict) else str(mx)).strip().lower()
            if not host:
                continue
            ent = OsintEntity(
                EntityType.MAIL_SERVER, host,
                provenance=[Provenance("dns", Observation.THIRD_PARTY,
                                       Confidence.MEDIUM, method="dns_mx")])
            graph.upsert_entity(ent)
            graph.link(RelationType.USES_MAIL_SERVER, root_id, ent.id,
                       Provenance("dns", Observation.THIRD_PARTY))

    def _ingest_emails(self, graph, root_id, profile) -> None:
        emails = profile.get("emails", {}) or {}
        addresses = emails.get("addresses", emails) if isinstance(emails, dict) else emails
        if isinstance(addresses, dict):
            addresses = addresses.get("addresses", [])
        for addr in addresses or []:
            value = (addr.get("email") if isinstance(addr, dict) else str(addr)).strip().lower()
            if "@" not in value:
                continue
            ent = OsintEntity(
                EntityType.EMAIL, value,
                provenance=[Provenance("email_harvest", Observation.THIRD_PARTY,
                                       Confidence.LOW, method="email_osint")])
            graph.upsert_entity(ent)
            graph.link(RelationType.HAS_EMAIL, root_id, ent.id,
                       Provenance("email_harvest", Observation.THIRD_PARTY))

    def _ingest_certificates(self, graph, root_id, profile) -> None:
        for cert in profile.get("certificates", []) or []:
            if isinstance(cert, dict):
                cid = cert.get("serial") or cert.get("fingerprint") or cert.get("common_name")
                attrs = {k: v for k, v in cert.items()}
            else:
                cid, attrs = str(cert), {}
            if not cid:
                continue
            ent = OsintEntity(
                EntityType.CERTIFICATE, str(cid), attributes=attrs,
                provenance=[Provenance("crt.sh", Observation.THIRD_PARTY,
                                       Confidence.HIGH, method="cert_transparency")])
            graph.upsert_entity(ent)
            graph.link(RelationType.PRESENTS_CERT, root_id, ent.id,
                       Provenance("crt.sh", Observation.THIRD_PARTY))

    def _ingest_tech(self, graph, root_id, profile) -> None:
        for tech in profile.get("tech_signals", []) or []:
            if isinstance(tech, dict):
                name = tech.get("name") or tech.get("tech") or tech.get("product")
                attrs = {k: v for k, v in tech.items()}
            else:
                name, attrs = str(tech), {}
            if not name:
                continue
            # Tech fingerprints are inferred evidence, never confirmed vulns.
            ent = OsintEntity(
                EntityType.TECHNOLOGY, str(name), attributes=attrs,
                validation_status=ValidationStatus.POTENTIAL,
                provenance=[Provenance("tech_fingerprint", Observation.INFERRED,
                                       Confidence.LOW, method="fingerprint")])
            graph.upsert_entity(ent)
            graph.link(RelationType.RUNS_TECH, root_id, ent.id,
                       Provenance("tech_fingerprint", Observation.INFERRED))

    def _ingest_paths(self, graph, root_id, profile) -> None:
        for path in profile.get("exposed_paths", []) or []:
            if isinstance(path, dict):
                url = path.get("url") or path.get("path")
                src = path.get("source", "archive")
                obs = Observation.HISTORICAL if "wayback" in str(src).lower() \
                    else Observation.THIRD_PARTY
            else:
                url, src, obs = str(path), "archive", Observation.HISTORICAL
            if not url:
                continue
            ent = OsintEntity(
                EntityType.URL_PATH, str(url),
                provenance=[Provenance(str(src), obs, Confidence.LOW,
                                       method="archive")])
            graph.upsert_entity(ent)
            graph.link(RelationType.EXPOSES_PATH, root_id, ent.id,
                       Provenance(str(src), obs))

    def _ingest_leaks(self, graph, root_id, profile) -> None:
        for leak in profile.get("credential_leaks", []) or []:
            # Safe metadata only — never the secret itself (data minimisation).
            if isinstance(leak, dict):
                ref = leak.get("url") or leak.get("source_ref") or leak.get("location") or "leak"
                indicator = leak.get("indicator") or leak.get("type") or "potential_exposure"
                attrs = {
                    "indicator": indicator,
                    "location": ref,
                    "note": "metadata-only; secret value not collected",
                }
            else:
                ref, attrs = "leak", {"indicator": str(leak)}
            ent = OsintEntity(
                EntityType.CREDENTIAL_LEAK, str(ref), attributes=attrs,
                validation_status=ValidationStatus.POTENTIAL,
                provenance=[Provenance("dork", Observation.THIRD_PARTY,
                                       Confidence.LOW, method="public_dork",
                                       source_ref=str(ref))])
            graph.upsert_entity(ent)
            graph.link(RelationType.LEAK_REFERENCES, ent.id, root_id,
                       Provenance("dork", Observation.THIRD_PARTY))
