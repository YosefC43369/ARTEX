"""
penetration_testing.intelligence.signatures
============================================

A maintained detection-signature library for accurate finding classification
and reporting (serves "update techniques so reports are accurate").

For each vulnerability class it holds:
* ``cwe``        — the CWE identifier (for standards-aligned reports),
* ``mitre``      — relevant MITRE ATT&CK technique ids,
* ``indicators`` — response/content signatures that *indicate* the issue was
  observed (used to corroborate a finding and reduce false positives — these
  match evidence, they are not weaponized payloads),
* ``references`` — authoritative references.

This is detection metadata only: it classifies and corroborates what the active
modules already observed; it does not exploit anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Signature:
    category: str
    cwe: str = ""
    mitre: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)   # raw regex
    references: List[str] = field(default_factory=list)
    _compiled: List[re.Pattern] = field(default_factory=list, repr=False)

    def __post_init__(self):
        self._compiled = [re.compile(p, re.I) for p in self.indicators]

    def matches(self, text: Optional[str]) -> List[str]:
        if not text:
            return []
        return [p.pattern for p in self._compiled if p.search(text)]


# Detection-signature catalogue. Indicators are *evidence* patterns (error
# banners, resolved-entity markers, engine fingerprints) — the things a scanner
# sees in a response when a class is present. Kept current per class.
_RAW: Dict[str, Dict] = {
    "sql_injection": {
        "cwe": "CWE-89", "mitre": ["T1190"],
        "indicators": [
            r"SQL syntax.*MySQL", r"Warning.*\bmysqli?_", r"PostgreSQL.*ERROR",
            r"ORA-\d{5}", r"Microsoft OLE DB Provider for SQL Server",
            r"SQLITE_ERROR", r"unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
        ],
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    "cross_site_scripting": {
        "cwe": "CWE-79", "mitre": ["T1059.007"],
        "indicators": [r"<script>.*</script>", r"on(error|load)\s*=", r"javascript:"],
        "references": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "ssrf": {
        "cwe": "CWE-918", "mitre": ["T1190"],
        "indicators": [
            r"169\.254\.169\.254", r"metadata\.google\.internal",
            r"ami-id|instance-id|iam/security-credentials",
            r"Connection refused|Could not resolve host",
        ],
        "references": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    },
    "server_side_template_injection": {
        "cwe": "CWE-1336", "mitre": ["T1190"],
        "indicators": [
            r"\b1337(331|7)\b",  # marker arithmetic result often used in SSTI probes
            r"jinja2\.exceptions", r"freemarker\.core", r"Twig\\Error",
            r"org\.apache\.velocity",
        ],
        "references": ["https://portswigger.net/web-security/server-side-template-injection"],
    },
    "xml_external_entity": {
        "cwe": "CWE-611", "mitre": ["T1190"],
        "indicators": [r"root:.*:0:0:", r"\bDOCTYPE\b.*\bENTITY\b", r"SYSTEM\s+\"file:"],
        "references": ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
    },
    "path_traversal": {
        "cwe": "CWE-22", "mitre": ["T1083"],
        "indicators": [r"root:.*:0:0:", r"\[extensions\]|\[fonts\]",  # win.ini
                       r"/etc/passwd", r"boot\.ini"],
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal"],
    },
    "broken_access_control": {
        "cwe": "CWE-284", "mitre": ["T1190"],
        "indicators": [r"\b200\b.*admin", r"X-Original-URL|X-Rewrite-URL"],
        "references": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    },
    "idor_bola": {
        "cwe": "CWE-639", "mitre": ["T1190"],
        "indicators": [],
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
    },
    "jwt_weakness": {
        "cwe": "CWE-347", "mitre": ["T1552"],
        "indicators": [r"\"alg\"\s*:\s*\"none\"", r"\"alg\"\s*:\s*\"HS256\""],
        "references": ["https://portswigger.net/web-security/jwt"],
    },
    "cors_misconfiguration": {
        "cwe": "CWE-942", "mitre": ["T1190"],
        "indicators": [r"access-control-allow-origin:\s*\*",
                       r"access-control-allow-credentials:\s*true"],
        "references": ["https://portswigger.net/web-security/cors"],
    },
    "missing_security_headers": {
        "cwe": "CWE-693", "mitre": ["T1190"],
        "indicators": [],
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    "tls_weakness": {
        "cwe": "CWE-326", "mitre": ["T1040"],
        "indicators": [r"SSLv3|TLSv1\.0|TLSv1\.1", r"expired|self.signed"],
        "references": ["https://wiki.mozilla.org/Security/Server_Side_TLS"],
    },
    "open_redirect": {
        "cwe": "CWE-601", "mitre": ["T1204"],
        "indicators": [r"location:\s*https?://(?!(?:[a-z0-9.-]*\.)?target)"],
        "references": ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
    },
    "information_exposure": {
        "cwe": "CWE-200", "mitre": ["T1592"],
        "indicators": [r"stack trace|Traceback \(most recent call last\)",
                       r"X-Powered-By|Server:\s"],
        "references": ["https://owasp.org/www-community/Improper_Error_Handling"],
    },
    # ── modern classes ──────────────────────────────────────────────────────
    "graphql_exposure": {
        "cwe": "CWE-16", "mitre": ["T1190"],
        "indicators": [r"__schema|__type", r"\"data\"\s*:\s*\{\s*\"__schema\"",
                       r"GraphQL", r"query(Type|Root)"],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "prototype_pollution": {
        "cwe": "CWE-1321", "mitre": ["T1059.007"],
        "indicators": [r"__proto__", r"constructor\s*\.\s*prototype"],
        "references": ["https://portswigger.net/web-security/prototype-pollution"],
    },
    "mass_assignment": {
        "cwe": "CWE-915", "mitre": ["T1190"],
        "indicators": [r"\"(is_?admin|role|isAdmin|privilege|verified)\"\s*:\s*(true|\"admin\")"],
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
    },
    "oauth_saml_misconfig": {
        "cwe": "CWE-287", "mitre": ["T1550"],
        "indicators": [r"redirect_uri=", r"SAMLResponse", r"response_type=token",
                       r"id_token"],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "http_request_smuggling": {
        "cwe": "CWE-444", "mitre": ["T1190"],
        "indicators": [r"Transfer-Encoding:\s*chunked", r"Content-Length:.*Transfer-Encoding"],
        "references": ["https://portswigger.net/web-security/request-smuggling"],
    },
    "security_misconfiguration": {
        "cwe": "CWE-16", "mitre": ["T1190"],
        "indicators": [r"Index of /", r"phpinfo\(\)", r"debug\s*=\s*true"],
        "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
    },
}


class SignatureLibrary:
    def __init__(self):
        self._sigs: Dict[str, Signature] = {
            k: Signature(category=k, cwe=v.get("cwe", ""), mitre=v.get("mitre", []),
                         indicators=v.get("indicators", []),
                         references=v.get("references", []))
            for k, v in _RAW.items()
        }

    def get(self, category: str) -> Optional[Signature]:
        return self._sigs.get(category)

    def mapping(self, category: str) -> Dict[str, object]:
        s = self._sigs.get(category)
        if not s:
            return {"cwe": "", "mitre": [], "references": []}
        return {"cwe": s.cwe, "mitre": list(s.mitre), "references": list(s.references)}

    def corroborate(self, category: str, text: Optional[str]) -> List[str]:
        """Return the indicator patterns that match the given evidence text."""
        s = self._sigs.get(category)
        return s.matches(text) if s else []

    def categories(self) -> List[str]:
        return list(self._sigs.keys())
