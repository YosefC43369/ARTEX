"""
penetration_testing.intelligence.people_osint
==============================================

People / entity intelligence layer for authorized red-team engagements.

Scope of this module
--------------------
During an authorized engagement the operator needs a picture of the *human*
attack surface of the **target organization** — the names, roles, work emails,
public handles and reachable phone numbers that a phishing-simulation or a
social-engineering scope would legitimately cover. This is the same category of
work done by theHarvester, SpiderFoot, Recon-ng and Maltego.

What this layer deliberately does **not** do
---------------------------------------------
* It is **not** a surveillance / dossier engine for arbitrary private people.
  Every person is filtered through an engagement **scope predicate**; people who
  do not belong to the target organization are dropped, not graphed.
* It reads **public sources only**. It never accesses private accounts, never
  authenticates as anyone, and never bypasses auth, CAPTCHA, paywalls or a
  platform's rate limits / ToS.
* It is **data-minimised**. Phone numbers and emails are redacted in serialised
  output by default, and any secret-bearing field a collector hands in
  (passwords, hashes, tokens, card/SSN data) is stripped on ingest and never
  stored — breach findings are kept as *metadata only* (which breach, which data
  classes), never the leaked secret itself.

The module produces :class:`~penetration_testing.intelligence.osint.OsintEntity`
records into an :class:`~penetration_testing.intelligence.osint.OsintGraph`, so
person intelligence merges into the same graph the infrastructure layer builds.
Collectors are dependency-injected, which keeps the whole thing offline-testable.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol

from ..constants import Confidence, ValidationStatus
from .osint import (
    EntityType,
    Observation,
    OsintEntity,
    OsintGraph,
    Provenance,
    RelationType,
)

# Fields that must never be persisted, whatever a collector hands us.
_SECRET_KEYS = frozenset({
    "password", "passwd", "pwd", "pass", "secret", "hash", "ntlm", "token",
    "api_key", "apikey", "otp", "pin", "ssn", "national_id", "credit_card",
    "card_number", "cvv", "private_key", "cookie", "session",
})

# Calling-code → (ISO country, display name). Intentionally a small, honest map
# used only for metadata tagging — not an owner/location lookup.
_CALLING_CODES = {
    "1": ("US/CA", "North America"), "44": ("GB", "United Kingdom"),
    "33": ("FR", "France"), "49": ("DE", "Germany"), "61": ("AU", "Australia"),
    "66": ("TH", "Thailand"), "65": ("SG", "Singapore"), "60": ("MY", "Malaysia"),
    "81": ("JP", "Japan"), "82": ("KR", "South Korea"), "86": ("CN", "China"),
    "91": ("IN", "India"), "7": ("RU/KZ", "Russia / Kazakhstan"),
    "34": ("ES", "Spain"), "39": ("IT", "Italy"), "31": ("NL", "Netherlands"),
    "55": ("BR", "Brazil"), "852": ("HK", "Hong Kong"), "886": ("TW", "Taiwan"),
    "971": ("AE", "United Arab Emirates"),
}

_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _strip_secrets(data: Any) -> Dict[str, Any]:
    """Return a shallow copy of a dict with any secret-bearing key removed.

    This is the data-minimisation gate: a collector can be sloppy and include a
    leaked password; it will not survive ingest.
    """
    if not isinstance(data, dict):
        return {}
    return {
        k: v for k, v in data.items()
        if k.lower() not in _SECRET_KEYS
    }


# ── phone metadata (offline, no owner lookup) ────────────────────────────────
@dataclass
class PhoneMetadata:
    e164: str
    country_code: str
    country: str
    region: str
    national_number: str
    valid: bool

    def to_attributes(self) -> Dict[str, Any]:
        return {
            "country_code": self.country_code,
            "country": self.country,
            "region": self.region,
            "valid_format": self.valid,
            "line_type": "unknown",   # honest: not derivable offline
        }


class PhoneIntel:
    """Parses a raw phone string into *format metadata* only.

    It answers "what country/region does this number's prefix indicate and is
    its shape plausible" — it does **not** look up who owns it or where they are.
    """

    @staticmethod
    def parse(raw: str) -> Optional[PhoneMetadata]:
        if not raw:
            return None
        has_plus = raw.strip().startswith("+") or raw.strip().startswith("00")
        digits = re.sub(r"\D", "", raw)
        if raw.strip().startswith("00"):
            digits = digits[2:]
        if not (7 <= len(digits) <= 15):
            return None

        cc, country, region = "", "unknown", "unknown"
        if has_plus:
            for length in (3, 2, 1):
                prefix = digits[:length]
                if prefix in _CALLING_CODES:
                    cc = prefix
                    region, country = _CALLING_CODES[prefix]
                    break
        national = digits[len(cc):] if cc else digits
        e164 = ("+" + digits) if has_plus else digits
        return PhoneMetadata(
            e164=e164, country_code=cc or "unknown", country=country,
            region=region, national_number=national,
            valid=bool(national) and len(national) >= 6,
        )


# ── username existence enumeration (public profiles only) ────────────────────
# Default registry of public profile URL templates. Checking whether a public
# profile page exists is equivalent to visiting it in a browser — no auth, no
# private content. The checker is injectable and rate-limited.
DEFAULT_PLATFORMS: Dict[str, str] = {
    "github": "https://github.com/{u}",
    "gitlab": "https://gitlab.com/{u}",
    "reddit": "https://www.reddit.com/user/{u}",
    "keybase": "https://keybase.io/{u}",
    "mastodon_social": "https://mastodon.social/@{u}",
    "medium": "https://medium.com/@{u}",
    "dev_to": "https://dev.to/{u}",
    "hackernews": "https://news.ycombinator.com/user?id={u}",
}


@dataclass
class UsernameHit:
    handle: str
    platform: str
    url: str
    exists: Optional[bool]   # True / False / None (indeterminate)


class UsernameEnumerator:
    """Checks whether a handle maps to a *public* profile on a set of platforms.

    Parameters
    ----------
    checker:
        ``(url: str) -> Optional[bool]`` — True if the public profile exists,
        False if it clearly does not, None if indeterminate. Injected for tests;
        a conservative urllib-based default is built lazily. Only public,
        unauthenticated GETs are ever issued.
    platforms:
        Mapping of platform name → URL template containing ``{u}``.
    rate_limit_seconds:
        Minimum delay between outbound checks (politeness / ToS). Ignored for an
        injected checker in tests via ``sleeper``.
    """

    def __init__(
        self,
        checker: Optional[Callable[[str], Optional[bool]]] = None,
        platforms: Optional[Dict[str, str]] = None,
        rate_limit_seconds: float = 1.0,
        sleeper: Callable[[float], None] = time.sleep,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._checker = checker
        self.platforms = platforms or dict(DEFAULT_PLATFORMS)
        self.rate_limit_seconds = rate_limit_seconds
        self._sleeper = sleeper
        self.logger = logger or logging.getLogger("artex.osint.people")

    def _default_checker(self, url: str) -> Optional[bool]:
        # Lazy, conservative, unauthenticated existence probe.
        import urllib.request
        import urllib.error
        req = urllib.request.Request(
            url, method="GET",
            headers={"User-Agent": "ARTEX-OSINT/1.0 (authorized recon)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return 200 <= resp.status < 300
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                return False
            return None
        except Exception:
            return None

    def enumerate(self, handle: str) -> List[UsernameHit]:
        handle = (handle or "").strip().lstrip("@")
        if not _USERNAME_RE.match(handle):
            return []
        checker = self._checker or self._default_checker
        hits: List[UsernameHit] = []
        for i, (platform, template) in enumerate(self.platforms.items()):
            if i and self._checker is None:
                self._sleeper(self.rate_limit_seconds)  # only throttle live net
            url = template.format(u=handle)
            try:
                exists = checker(url)
            except Exception:
                exists = None
            hits.append(UsernameHit(handle, platform, url, exists))
        return hits


# ── collector protocol ───────────────────────────────────────────────────────
class PeopleCollector(Protocol):
    """Any object able to return a people-intelligence profile for a target.

    Returns a dict shaped like::

        {
          "organization": {"name": str, "domain": str},
          "people": [
             {"name": str, "role": str, "emails": [str, ...],
              "phones": [str, ...],
              "usernames": [{"handle": str, "platform": str, "url": str}, ...],
              "profile_urls": [str, ...], "source": str}
          ],
          "breach_exposures": [
             {"email": str, "breach": str, "date": str,
              "data_classes": [str, ...], "source": str}   # metadata only
          ],
        }
    """

    def collect(self, target: str, scope: Optional[Any] = None,
                deep: bool = False) -> Dict[str, Any]:
        ...


# ── engine ───────────────────────────────────────────────────────────────────
class PeopleIntelligenceEngine:
    """Normalises a people collector's output into an :class:`OsintGraph`.

    Parameters
    ----------
    collector:
        A :class:`PeopleCollector`. Injected for testability; required for live
        use (there is no default live collector — collection is the operator's
        choice of ToS-respecting source).
    in_scope:
        ``(person: dict, target: str) -> bool``. Defaults to
        "person has a work email on the target domain, or is affiliated with the
        target org/domain". Out-of-scope people are dropped.
    redact:
        Redact email/phone values in serialised output (default True).
    """

    def __init__(
        self,
        collector: Optional[PeopleCollector] = None,
        in_scope: Optional[Callable[[Dict[str, Any], str], bool]] = None,
        redact: bool = True,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._collector = collector
        self._in_scope = in_scope
        self.redact = redact
        self.logger = logger or logging.getLogger("artex.osint.people")
        self.skipped_out_of_scope = 0

    # -- scope ----------------------------------------------------------------
    def _scope_ok(self, person: Dict[str, Any], target: str,
                  org_name: str) -> bool:
        if self._in_scope is not None:
            return self._in_scope(person, target)
        target = (target or "").strip().lower().rstrip(".")
        for email in person.get("emails", []) or []:
            dom = str(email).partition("@")[2].strip().lower()
            if dom and (dom == target or dom.endswith("." + target)):
                return True
        aff = str(person.get("affiliation") or person.get("organization") or "").lower()
        if org_name and org_name.lower() in aff:
            return True
        if target and target in aff:
            return True
        return False

    # -- public API -----------------------------------------------------------
    def investigate(
        self,
        target: str,
        graph: Optional[OsintGraph] = None,
        deep: bool = False,
        scope: Optional[Any] = None,
    ) -> OsintGraph:
        root = (target or "").strip().lower().rstrip(".")
        if not root:
            raise ValueError("investigate() requires a non-empty target")
        if self._collector is None:
            raise ValueError("PeopleIntelligenceEngine requires a collector")

        graph = graph if graph is not None else OsintGraph()
        self.skipped_out_of_scope = 0
        profile = self._collector.collect(root, scope=scope, deep=deep) or {}

        org = profile.get("organization", {}) or {}
        org_name = str(org.get("name") or root)
        org_ent = OsintEntity(
            EntityType.ORGANIZATION, org_name,
            attributes={"domain": org.get("domain", root)},
            validation_status=ValidationStatus.CONFIRMED,
            provenance=[Provenance("artex", Observation.OBSERVED,
                                   Confidence.HIGH, method="target")],
        )
        graph.upsert_entity(org_ent)
        org_id = org_ent.id

        for person in profile.get("people", []) or []:
            self._ingest_person(graph, person, root, org_name, org_id)

        self._ingest_breaches(graph, profile)

        self.logger.info(
            "People intelligence done — %d entities, %d relationships "
            "(%d people dropped as out-of-scope)",
            len(graph.entities), len(graph.relationships),
            self.skipped_out_of_scope,
        )
        return graph

    # -- ingesters ------------------------------------------------------------
    def _ingest_person(self, graph, person, target, org_name, org_id) -> None:
        if not isinstance(person, dict):
            return
        name = str(person.get("name") or "").strip()
        if not name:
            return
        if not self._scope_ok(person, target, org_name):
            self.skipped_out_of_scope += 1
            return

        source = str(person.get("source") or "people_osint")
        attrs = _strip_secrets(person)
        # keep only safe, useful person attributes
        safe = {k: attrs[k] for k in ("role", "title", "affiliation",
                                      "location", "profile_urls")
                if k in attrs}
        p_ent = OsintEntity(
            EntityType.PERSON, name, attributes=safe,
            validation_status=ValidationStatus.POTENTIAL,
            provenance=[Provenance(source, Observation.THIRD_PARTY,
                                   Confidence.LOW, method="people_osint")],
        )
        graph.upsert_entity(p_ent)
        graph.link(RelationType.AFFILIATED_WITH, p_ent.id, org_id,
                   Provenance(source, Observation.THIRD_PARTY))

        for email in person.get("emails", []) or []:
            value = str(email).strip().lower()
            if "@" not in value:
                continue
            e_ent = OsintEntity(
                EntityType.EMAIL, value,
                provenance=[Provenance(source, Observation.THIRD_PARTY,
                                       Confidence.LOW, method="email_osint")])
            graph.upsert_entity(e_ent)
            graph.link(RelationType.HAS_EMAIL, p_ent.id, e_ent.id,
                       Provenance(source, Observation.THIRD_PARTY))

        for phone in person.get("phones", []) or []:
            meta = PhoneIntel.parse(str(phone))
            if meta is None:
                continue
            ph_ent = OsintEntity(
                EntityType.PHONE, meta.e164, attributes=meta.to_attributes(),
                provenance=[Provenance(source, Observation.THIRD_PARTY,
                                       Confidence.LOW, method="phone_metadata")])
            graph.upsert_entity(ph_ent)
            graph.link(RelationType.HAS_PHONE, p_ent.id, ph_ent.id,
                       Provenance(source, Observation.THIRD_PARTY))

        for uname in person.get("usernames", []) or []:
            self._ingest_username(graph, p_ent.id, uname, source)

    def _ingest_username(self, graph, person_id, uname, source) -> None:
        if isinstance(uname, dict):
            handle = str(uname.get("handle") or "").strip().lstrip("@")
            platform = str(uname.get("platform") or "")
            url = str(uname.get("url") or "")
            exists = uname.get("exists")
        else:
            handle, platform, url, exists = str(uname).strip().lstrip("@"), "", "", None
        if not handle:
            return
        u_ent = OsintEntity(
            EntityType.USERNAME, handle,
            provenance=[Provenance(source, Observation.THIRD_PARTY,
                                   Confidence.LOW, method="username_osint")])
        graph.upsert_entity(u_ent)
        graph.link(RelationType.HAS_USERNAME, person_id, u_ent.id,
                   Provenance(source, Observation.THIRD_PARTY))

        if platform and url and exists is not False:
            # Confirmed-public profiles are observed; unverified ones inferred.
            obs = Observation.THIRD_PARTY if exists else Observation.INFERRED
            conf = Confidence.MEDIUM if exists else Confidence.LOW
            prof = OsintEntity(
                EntityType.SOCIAL_PROFILE, url,
                attributes={"platform": platform, "handle": handle,
                            "verified_public": bool(exists)},
                validation_status=ValidationStatus.POTENTIAL,
                provenance=[Provenance(f"{source}:{platform}", obs, conf,
                                       method="profile_existence",
                                       source_ref=url)])
            graph.upsert_entity(prof)
            graph.link(RelationType.HAS_PROFILE, u_ent.id, prof.id,
                       Provenance(f"{source}:{platform}", obs))

    def _ingest_breaches(self, graph, profile) -> None:
        for leak in profile.get("breach_exposures", []) or []:
            if not isinstance(leak, dict):
                continue
            email = str(leak.get("email") or "").strip().lower()
            breach_name = str(leak.get("breach") or leak.get("name") or "").strip()
            if not breach_name:
                continue
            # Metadata only — never the secret. Strip then keep a safe subset.
            safe = _strip_secrets(leak)
            b_ent = OsintEntity(
                EntityType.BREACH, breach_name,
                attributes={
                    "date": safe.get("date", ""),
                    "data_classes": safe.get("data_classes", []),
                    "source": safe.get("source", "breach_index"),
                    "note": "metadata-only; no credential value collected",
                },
                validation_status=ValidationStatus.POTENTIAL,
                provenance=[Provenance(str(safe.get("source") or "breach_index"),
                                       Observation.THIRD_PARTY, Confidence.LOW,
                                       method="breach_metadata")])
            graph.upsert_entity(b_ent)
            if "@" in email:
                e_ent = OsintEntity(
                    EntityType.EMAIL, email,
                    provenance=[Provenance("breach_index", Observation.THIRD_PARTY,
                                           Confidence.LOW, method="breach_metadata")])
                graph.upsert_entity(e_ent)
                graph.link(RelationType.APPEARS_IN_BREACH, e_ent.id, b_ent.id,
                           Provenance("breach_index", Observation.THIRD_PARTY))
