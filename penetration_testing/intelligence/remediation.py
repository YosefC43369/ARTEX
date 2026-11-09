"""
penetration_testing.intelligence.remediation
=============================================

Report enrichment: attaches standards-aligned remediation guidance, CWE/MITRE
ids and authoritative references to every finding so the generated report is
complete and actionable (serves "accurate, useful reports").

Design notes
------------
* Keyed by the same category string used everywhere else — ``VulnCategory``
  values are identical to the detection-signature keys, so one key space covers
  signatures, validation and remediation.
* Enrichment is **non-promoting and non-destructive to meaning**: it only fills
  blank ``remediation``/``references`` fields and stamps ``cwe``/``mitre`` when
  the finding does not already carry them. It never changes a finding's
  validation status, severity or title.
* Remediation text is defensive guidance (how to *fix* the class), not attack
  instruction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..models import Finding
from .signatures import SignatureLibrary


@dataclass
class Remediation:
    summary: str = ""
    steps: List[str] = field(default_factory=list)

    def as_text(self) -> str:
        if not self.summary and not self.steps:
            return ""
        parts = [self.summary] if self.summary else []
        parts += [f"({i}) {s}" for i, s in enumerate(self.steps, 1)]
        return " ".join(parts)


# Category -> remediation guidance. Keys match VulnCategory values / signature
# keys exactly. Guidance is concise, prioritised and framework-neutral.
_REMEDIATION: Dict[str, Remediation] = {
    "sql_injection": Remediation(
        "Use parameterised queries / prepared statements for every database call.",
        ["Never build SQL by string concatenation with user input.",
         "Apply least-privilege DB accounts (no DDL/DROP from the app user).",
         "Use an ORM or query builder with bound parameters; validate input types.",
         "Add a WAF rule as defence-in-depth, not as the primary control."]),
    "cross_site_scripting": Remediation(
        "Context-aware output encoding plus a strict Content-Security-Policy.",
        ["HTML-encode on output; use framework auto-escaping and keep it on.",
         "Set CSP with no unsafe-inline/unsafe-eval; use nonces or hashes.",
         "Sanitise rich HTML with an allowlist library (e.g. DOMPurify).",
         "Set HttpOnly on session cookies so XSS cannot read them."]),
    "ssrf": Remediation(
        "Deny-by-default egress and strict URL allowlisting for server fetches.",
        ["Allowlist destination hosts/schemes; reject raw IPs and redirects.",
         "Block link-local/metadata ranges (169.254.0.0/16, cloud metadata IPs).",
         "Enforce IMDSv2 / disable instance metadata where unused.",
         "Resolve and re-validate the final IP after redirects (anti-DNS-rebind)."]),
    "server_side_template_injection": Remediation(
        "Never render user input as a template; use logic-less, sandboxed templates.",
        ["Pass user data as template variables, not as template source.",
         "Use a sandboxed engine configuration and disable dangerous builtins.",
         "Validate/escape any value that must reach template context."]),
    "xml_external_entity": Remediation(
        "Disable external entity and DTD processing in every XML parser.",
        ["Set the parser to forbid DOCTYPE/external entities (XXE-safe flags).",
         "Prefer JSON or a hardened parser; disable entity expansion.",
         "Validate uploaded XML against a schema without external refs."]),
    "path_traversal": Remediation(
        "Canonicalise paths and confine file access to an allowlisted base directory.",
        ["Reject input containing path separators or traversal sequences.",
         "Resolve the real path and verify it stays under the intended root.",
         "Map user input to opaque IDs instead of filesystem paths."]),
    "broken_access_control": Remediation(
        "Enforce server-side authorization on every request against the object owner.",
        ["Deny by default; check permissions on each resource server-side.",
         "Do not rely on hidden fields, client roles or header overrides.",
         "Re-test with a low-privilege session for every privileged route."]),
    "idor_bola": Remediation(
        "Verify object ownership on every access; use unguessable references.",
        ["Check that the authenticated principal owns the requested object.",
         "Replace sequential IDs with UUIDs/indirect references where feasible.",
         "Add automated access-control tests per object type."]),
    "authentication_weakness": Remediation(
        "Harden authentication: MFA, rate limiting and uniform error responses.",
        ["Return identical messages for unknown user vs wrong password.",
         "Rate-limit and lock out after repeated failures; add MFA.",
         "Store passwords with a strong adaptive hash (argon2/bcrypt/scrypt).",
         "Remove default/shared credentials."]),
    "session_security": Remediation(
        "Issue secure session cookies and rotate identifiers on privilege change.",
        ["Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.",
         "Regenerate the session ID on login and privilege elevation.",
         "Enforce idle and absolute session timeouts; invalidate on logout."]),
    "api_authorization": Remediation(
        "Apply function-level authorization checks on every API operation.",
        ["Enforce role/scope checks server-side for each endpoint and method.",
         "Default-deny unknown routes; do not expose admin ops by obscurity.",
         "Validate token scope/audience on every request."]),
    "business_logic": Remediation(
        "Validate state transitions and monetary/quantity values server-side.",
        ["Reject negative or out-of-range quantities, prices and discounts.",
         "Enforce the intended workflow order; recompute totals on the server.",
         "Add invariants and abuse-case tests for critical flows."]),
    "security_misconfiguration": Remediation(
        "Harden deployment: disable debug, remove defaults, restrict surfaces.",
        ["Turn off debug/stack traces and verbose errors in production.",
         "Remove sample apps, admin consoles and directory listing.",
         "Apply a hardening baseline and track config drift."]),
    "information_exposure": Remediation(
        "Suppress verbose errors and keep secrets out of responses and repos.",
        ["Return generic error pages; log details server-side only.",
         "Strip version/stack banners; remove secrets from code and headers.",
         "Block access to VCS/metadata files (.git, .env, .svn)."]),
    "subdomain_takeover": Remediation(
        "Remove dangling DNS records pointing at unclaimed external services.",
        ["Audit CNAME/ALIAS records for decommissioned providers.",
         "Delete or reclaim the dangling target before an attacker does.",
         "Add monitoring for records resolving to unclaimed endpoints."]),
    "tls_weakness": Remediation(
        "Serve TLS 1.2+ with modern ciphers and a valid certificate chain.",
        ["Disable SSLv3/TLS1.0/1.1 and weak ciphers (RC4/3DES/EXPORT/NULL).",
         "Deploy a valid, non-expired certificate with the full chain.",
         "Enable HSTS once HTTPS is enforced everywhere."]),
    "missing_security_headers": Remediation(
        "Send the baseline security response headers on every response.",
        ["Add CSP, X-Content-Type-Options: nosniff and a frame policy.",
         "Add HSTS, Referrer-Policy and a least-privilege Permissions-Policy.",
         "Verify headers in CI so they cannot regress."]),
    "open_redirect": Remediation(
        "Never redirect to raw user-supplied URLs; use an allowlist or mapping.",
        ["Validate redirect targets against an allowlist of internal paths.",
         "Map tokens to destinations instead of taking full URLs.",
         "Reject absolute/protocol-relative URLs in redirect parameters."]),
    "cors_misconfiguration": Remediation(
        "Reflect only explicitly trusted origins and avoid wildcard-with-credentials.",
        ["Maintain an allowlist of origins; never reflect arbitrary Origin.",
         "Never combine Allow-Origin: * (or null) with credentials.",
         "Scope CORS to the specific endpoints that need it."]),
    "jwt_weakness": Remediation(
        "Pin the signing algorithm, verify signatures and reject 'none'.",
        ["Reject alg=none and disallow algorithm switching (RS<->HS confusion).",
         "Verify signature with the expected key; validate exp/iss/aud.",
         "Do not trust kid/jku/x5u header values to fetch keys."]),
    "graphql_exposure": Remediation(
        "Disable introspection and field suggestions in production; add limits.",
        ["Turn off introspection and 'did you mean' suggestions publicly.",
         "Enforce query depth/complexity limits and per-field authorization.",
         "Disable the GraphiQL/Playground console in production."]),
    "prototype_pollution": Remediation(
        "Block __proto__/constructor keys and use safe object handling.",
        ["Reject __proto__, constructor and prototype keys in input.",
         "Use Map or null-prototype objects for untrusted key/value data.",
         "Patch vulnerable merge/clone utility dependencies."]),
    "mass_assignment": Remediation(
        "Bind only allowlisted fields; never trust client-supplied privileged attrs.",
        ["Use explicit input DTOs/allowlists; ignore unknown fields.",
         "Separate internal flags (role, is_admin, balance) from writable models.",
         "Add tests that privileged fields cannot be set via the API."]),
    "oauth_saml_misconfig": Remediation(
        "Enforce exact redirect_uri matching, state/nonce and token integrity.",
        ["Exact-match registered redirect_uri; disallow open redirects.",
         "Require and verify state (CSRF) and nonce (replay) values.",
         "Use the authorization-code flow with PKCE; keep tokens out of URLs.",
         "Validate SAML signatures and the AssertionConsumerService URL."]),
    "http_request_smuggling": Remediation(
        "Normalise request framing between front-end and back-end servers.",
        ["Reject messages with both Content-Length and Transfer-Encoding.",
         "Use HTTP/2 end-to-end or a parser that rejects ambiguous framing.",
         "Keep front-end and origin parsing behaviour aligned and patched."]),
}


class RemediationAdvisor:
    """Attaches remediation, references and CWE/MITRE to findings."""

    def __init__(self, signatures: Optional[SignatureLibrary] = None):
        self.signatures = signatures or SignatureLibrary()

    def advise(self, category: str) -> Remediation:
        return _REMEDIATION.get(category, Remediation())

    def enrich(self, finding: Finding) -> Finding:
        category = getattr(finding.category, "value", str(finding.category))
        mapping = self.signatures.mapping(category)

        # CWE / MITRE — only stamp when absent (validation may already have done it)
        if not finding.cwe and mapping.get("cwe"):
            finding.cwe = mapping["cwe"]
        if not finding.mitre and mapping.get("mitre"):
            finding.mitre = list(mapping["mitre"])

        # References — fill when the finding carries none
        if not finding.references and mapping.get("references"):
            finding.references = list(mapping["references"])

        # Remediation — fill only when blank, so analysis-supplied text wins
        if not finding.remediation:
            text = self.advise(category).as_text()
            if text:
                finding.remediation = text

        return finding

    def enrich_findings(self, findings: List[Finding]) -> List[Finding]:
        return [self.enrich(f) for f in findings]

    def enrich_session(self, session) -> int:
        """Enrich every finding on a session. Returns the count enriched."""
        self.enrich_findings(session.findings)
        return len(session.findings)

    def categories(self) -> List[str]:
        return list(_REMEDIATION.keys())
