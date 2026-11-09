"""
penetration_testing.constants
==============================

Central enumerations and immutable constants shared across the subsystem.

Keeping every state machine, taxonomy and tunable default in one module gives
the rest of the package a single source of truth and avoids the "magic string"
drift that makes multi-module systems fragile.
"""

from __future__ import annotations

from enum import Enum


SUBSYSTEM_NAME = "ARTEX-PenTest"
SUBSYSTEM_VERSION = "1.0.0"

# Default OpenRouter wiring — mirrors the convention already used by the
# existing modules/AI_*.py files so the subsystem does not introduce a second,
# divergent provider configuration.
DEFAULT_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_OPENROUTER_MODEL = "meta-llama/llama-3-70b-instruct"
OPENROUTER_API_KEY_ENV = "OPENROUTER_API_KEY"


class StrEnum(str, Enum):
    """A str-backed Enum so values serialize cleanly to JSON/XML."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class SessionState(StrEnum):
    CREATED = "created"
    PLANNING = "planning"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    DENIED = "denied"          # blocked by scope / permission policy
    AWAITING_APPROVAL = "awaiting_approval"   # held for human-in-the-loop
    CANCELLED = "cancelled"


# Bridge capability NAMES that require explicit human approval before execution
# (human-in-the-loop). Empty by default: ARTEX is an authorized red-team tool
# and config.xml is the authorization, so capabilities run without per-task
# friction. Operators who want a HITL gate can pass a non-empty set to
# ApprovalManager (e.g. {"attack.web_vuln"}).
DEFAULT_APPROVAL_CAPABILITIES: set = set()


class Phase(StrEnum):
    RECON = "recon"
    ENUMERATION = "enumeration"
    ANALYSIS = "analysis"
    TESTING = "testing"
    VALIDATION = "validation"
    REPORTING = "reporting"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
        }[self.value]


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ValidationStatus(StrEnum):
    """Keeps AI hypotheses strictly separated from verified observations."""

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INCONCLUSIVE = "inconclusive"
    FALSE_POSITIVE = "false_positive"


class VulnCategory(StrEnum):
    SQLI = "sql_injection"
    XSS = "cross_site_scripting"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    IDOR = "idor_bola"
    AUTH_WEAKNESS = "authentication_weakness"
    SESSION_WEAKNESS = "session_security"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    API_AUTHZ = "api_authorization"
    MISCONFIGURATION = "security_misconfiguration"
    INFO_EXPOSURE = "information_exposure"
    BUSINESS_LOGIC = "business_logic"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    TLS_WEAKNESS = "tls_weakness"
    MISSING_HEADERS = "missing_security_headers"
    SSTI = "server_side_template_injection"
    XXE = "xml_external_entity"
    CORS = "cors_misconfiguration"
    JWT = "jwt_weakness"
    OPEN_REDIRECT = "open_redirect"
    # modern classes
    GRAPHQL = "graphql_exposure"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    MASS_ASSIGNMENT = "mass_assignment"
    OAUTH_SAML = "oauth_saml_misconfig"
    REQUEST_SMUGGLING = "http_request_smuggling"


class EvidenceKind(StrEnum):
    HTTP_EXCHANGE = "http_exchange"
    DNS_RECORD = "dns_record"
    TOOL_OUTPUT = "tool_output"
    OBSERVATION = "observation"
    TLS_DETAIL = "tls_detail"


# CVSS-like base score bands used by the severity calculator.
SEVERITY_SCORE_BANDS = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH: (7.0, 8.9),
    Severity.MEDIUM: (4.0, 6.9),
    Severity.LOW: (0.1, 3.9),
    Severity.INFO: (0.0, 0.0),
}

# Hard ceilings so an autonomous loop can never run unbounded, even if a
# config.xml omits them. The configuration layer may lower these but never
# raise them past the safety ceiling.
SAFETY_CEILINGS = {
    "max_iterations": 100,
    "max_runtime_seconds": 3600,
    "max_concurrency": 16,
    "max_requests_per_second": 20.0,
    "max_tasks": 500,
}
