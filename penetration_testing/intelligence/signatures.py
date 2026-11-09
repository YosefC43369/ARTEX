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
            # broadened engine/driver banners to cut false negatives
            r"You have an error in your SQL syntax",
            r"MySQLSyntaxErrorException|com\.mysql\.jdbc",
            r"MariaDB server version for the right syntax",
            r"SQLSTATE\[\w+\]", r"syntax error at or near",
            r"Unterminated string literal|org\.postgresql\.util\.PSQLException",
            r"System\.Data\.SqlClient\.SqlException|Incorrect syntax near",
            r"SQLException|JDBC|ODBC SQL Server Driver",
            r"DB2 SQL error|SQLCODE|Sybase message",
            r"valid MySQL result|mysql_fetch_(array|assoc|row)",
        ],
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    "cross_site_scripting": {
        "cwe": "CWE-79", "mitre": ["T1059.007"],
        "indicators": [
            r"<script>.*</script>", r"on(error|load|mouseover|focus|toggle)\s*=",
            r"javascript:", r"<svg[^>]*on\w+\s*=", r"<img[^>]+onerror\s*=",
            r"<iframe[^>]+srcdoc", r"alert\(\s*(?:document\.)?(?:domain|cookie)\s*\)",
            r"\bon\w+\s*=\s*[\"']?[^>]*confirm\(",
        ],
        "references": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "ssrf": {
        "cwe": "CWE-918", "mitre": ["T1190"],
        "indicators": [
            r"169\.254\.169\.254", r"metadata\.google\.internal",
            r"ami-id|instance-id|iam/security-credentials",
            r"Connection refused|Could not resolve host",
            # additional cloud metadata + scheme echoes
            r"100\.100\.100\.200",            # Alibaba Cloud metadata
            r"metadata/instance\?api-version", # Azure IMDS
            r"metadata\.packet\.net|169\.254\.169\.254/metadata",
            r"\"accessKeyId\"|\"SecretAccessKey\"|\"Token\"\s*:",
            r"gopher://|dict://|file:///(etc|proc)/",
            r"ComputeMetadata/v1|project-id\b",
        ],
        "references": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    },
    "server_side_template_injection": {
        "cwe": "CWE-1336", "mitre": ["T1190"],
        "indicators": [
            r"\b1337(331|7)\b",  # marker arithmetic result often used in SSTI probes
            r"\b49\b(?=.*7\s*\*\s*7)",          # 7*7 style marker
            r"jinja2\.exceptions", r"freemarker\.core", r"Twig\\Error",
            r"org\.apache\.velocity", r"smarty|Smarty_Internal",
            r"freemarker\.template\.|TemplateProcessingException",
            r"Mako|mako\.exceptions", r"Handlebars|Pebble",
        ],
        "references": ["https://portswigger.net/web-security/server-side-template-injection"],
    },
    "xml_external_entity": {
        "cwe": "CWE-611", "mitre": ["T1190"],
        "indicators": [
            r"root:.*:0:0:", r"\bDOCTYPE\b.*\bENTITY\b", r"SYSTEM\s+\"file:",
            r"\bENTITY\b.*SYSTEM", r"xmlParseEntityRef|undefined entity",
            r"DOCTYPE[^>]+SYSTEM\s+\"https?:", r"\[&\w+;\]|&xxe;",
            r"for 16-bit app support|\[fonts\]",   # win.ini via XXE
        ],
        "references": ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
    },
    "path_traversal": {
        "cwe": "CWE-22", "mitre": ["T1083"],
        "indicators": [
            r"root:.*:0:0:", r"\[extensions\]|\[fonts\]",  # win.ini
            r"/etc/passwd", r"boot\.ini", r"daemon:.*:/usr/sbin",
            r"\[boot loader\]|\[operating systems\]",
            r"MACHINE[\\/]SAM|ntuser\.dat", r"/proc/self/(environ|cmdline)",
            r"(?:\.\./|\.\.\\|%2e%2e[%2f%5c/]){2,}",   # encoded/raw traversal reflected
        ],
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal"],
    },
    "broken_access_control": {
        "cwe": "CWE-284", "mitre": ["T1190"],
        "indicators": [
            r"\b200\b.*admin", r"X-Original-URL|X-Rewrite-URL",
            r"X-Forwarded-For|X-Forwarded-Host|X-Custom-IP-Authorization",
            r"\"role\"\s*:\s*\"(admin|superuser|root)\"",
            r"HTTP/\d\.\d\s+200.*(?:/admin|/internal|/manage)",
        ],
        "references": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    },
    "idor_bola": {
        "cwe": "CWE-639", "mitre": ["T1190"],
        "indicators": [
            # echoes of another principal's object in a response to a swapped id
            r"\"(user_?id|account_?id|owner_?id|customer_?id)\"\s*:\s*\d+",
            r"\"email\"\s*:\s*\"[^\"]+@", r"\"ssn\"|\"tax_id\"|\"card_number\"",
        ],
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
    },
    "authentication_weakness": {
        "cwe": "CWE-287", "mitre": ["T1110"],
        "indicators": [
            r"WWW-Authenticate:\s*Basic", r"\"token\"\s*:\s*\"[A-Za-z0-9._-]{8,}\"",
            r"(invalid|incorrect)\s+(username|password)",  # user-enumeration oracle
            r"Set-Cookie:[^;]*(session|auth|sid)=[^;]+(?!.*Secure)",
            r"default\s+(credentials|password)|admin:admin",
        ],
        "references": ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    },
    "session_security": {
        "cwe": "CWE-384", "mitre": ["T1539"],
        "indicators": [
            r"Set-Cookie:[^;\r\n]*(?![^;]*HttpOnly)",   # cookie without HttpOnly
            r"Set-Cookie:[^;\r\n]*(?![^;]*Secure)",     # cookie without Secure
            r"Set-Cookie:[^;\r\n]*SameSite=None",
            r"PHPSESSID|JSESSIONID|ASP\.NET_SessionId",
        ],
        "references": ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
    },
    "api_authorization": {
        "cwe": "CWE-285", "mitre": ["T1190"],
        "indicators": [
            r"\"scope\"\s*:\s*\"[^\"]*\badmin\b", r"\"permissions\"\s*:\s*\[",
            r"HTTP/\d\.\d\s+200.*/api/.*(admin|internal|debug)",
            r"X-Api-Key|Authorization:\s*Bearer",
        ],
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"],
    },
    "business_logic": {
        "cwe": "CWE-840", "mitre": ["T1190"],
        "indicators": [
            r"\"(price|amount|total|quantity)\"\s*:\s*-?\d",
            r"\"(discount|coupon)\"\s*:\s*\"?\d+%?", r"\"status\"\s*:\s*\"(paid|approved)\"",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/"],
    },
    "subdomain_takeover": {
        "cwe": "CWE-350", "mitre": ["T1584.001"],
        "indicators": [
            r"There isn't a GitHub Pages site here",
            r"NoSuchBucket|The specified bucket does not exist",
            r"Fastly error: unknown domain|Heroku \| No such app",
            r"The requested URL was not found on this server\.\s*That.s all we know",
            r"Repository not found|Sorry, We Couldn.t Find That Page",
            r"CNAME.*(amazonaws|azurewebsites|cloudapp|github\.io|herokudns)",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"],
    },
    "jwt_weakness": {
        "cwe": "CWE-347", "mitre": ["T1552"],
        "indicators": [
            r"\"alg\"\s*:\s*\"none\"", r"\"alg\"\s*:\s*\"HS256\"",
            r"\"alg\"\s*:\s*\"(RS|ES|PS)256\"",     # RS->HS confusion surface
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",  # JWT in response/log
            r"invalid signature|jwt (expired|malformed)|JWSError",
            r"\"kid\"\s*:", r"\"jku\"\s*:|\"x5u\"\s*:",   # header-injection surface
        ],
        "references": ["https://portswigger.net/web-security/jwt"],
    },
    "cors_misconfiguration": {
        "cwe": "CWE-942", "mitre": ["T1190"],
        "indicators": [
            r"access-control-allow-origin:\s*\*",
            r"access-control-allow-credentials:\s*true",
            r"access-control-allow-origin:\s*null",
            r"access-control-allow-origin:\s*https?://[^\s]*\.?(evil|attacker)",
        ],
        "references": ["https://portswigger.net/web-security/cors"],
    },
    "missing_security_headers": {
        "cwe": "CWE-693", "mitre": ["T1190"],
        "indicators": [],
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    "tls_weakness": {
        "cwe": "CWE-326", "mitre": ["T1040"],
        "indicators": [
            r"SSLv2|SSLv3|TLSv1\.0|TLSv1\.1", r"expired|self.signed",
            r"RC4|3DES|DES-CBC|EXPORT|NULL-|MD5|anon",
            r"weak (cipher|key)|key too small|insecure renegotiation",
            r"certificate has expired|unable to get local issuer",
        ],
        "references": ["https://wiki.mozilla.org/Security/Server_Side_TLS"],
    },
    "open_redirect": {
        "cwe": "CWE-601", "mitre": ["T1204"],
        "indicators": [
            r"location:\s*https?://(?!(?:[a-z0-9.-]*\.)?target)",
            r"location:\s*//[^/\s]+", r"location:\s*https?:(\\/|%2f){2}",
            r"url=https?://|returnUrl=https?://|next=https?://",
        ],
        "references": ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
    },
    "information_exposure": {
        "cwe": "CWE-200", "mitre": ["T1592"],
        "indicators": [
            r"stack trace|Traceback \(most recent call last\)",
            r"X-Powered-By|Server:\s", r"X-AspNet-Version|X-AspNetMvc-Version",
            r"Exception|at [\w.]+\([\w.]+:\d+\)",   # Java/.NET stack frame
            r"DEBUG|Whoops, looks like something went wrong|Werkzeug Debugger",
            r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY",
            r"(api[_-]?key|secret|password|passwd)\"?\s*[:=]\s*\"?[A-Za-z0-9/_+-]{12,}",
            r"\.git/HEAD|\.env\b|/\.svn/|\bwp-config\.php",
        ],
        "references": ["https://owasp.org/www-community/Improper_Error_Handling"],
    },
    # ── modern classes ──────────────────────────────────────────────────────
    "graphql_exposure": {
        "cwe": "CWE-16", "mitre": ["T1190"],
        "indicators": [
            r"__schema|__type", r"\"data\"\s*:\s*\{\s*\"__schema\"",
            r"GraphQL", r"query(Type|Root)|mutationType",
            r"Did you mean \"[^\"]+\"\?",      # field-suggestion leak
            r"Cannot query field|Unknown argument|must not have a selection",
            r"\"extensions\"\s*:\s*\{[^}]*\"code\"", r"apollo|graphiql|/graphql",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "prototype_pollution": {
        "cwe": "CWE-1321", "mitre": ["T1059.007"],
        "indicators": [
            r"__proto__", r"constructor\s*\.\s*prototype",
            r"\"prototype\"\s*:", r"Object\.prototype\.\w+",
            r"polluted|__proto__.*injected",
        ],
        "references": ["https://portswigger.net/web-security/prototype-pollution"],
    },
    "mass_assignment": {
        "cwe": "CWE-915", "mitre": ["T1190"],
        "indicators": [
            r"\"(is_?admin|role|isAdmin|privilege|verified|is_?staff|is_?superuser)\"\s*:\s*(true|\"admin\")",
            r"\"(balance|credit|account_?type|plan)\"\s*:\s*\"?(premium|unlimited|\d)",
            r"\"(approved|active|enabled)\"\s*:\s*true",
        ],
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
    },
    "oauth_saml_misconfig": {
        "cwe": "CWE-287", "mitre": ["T1550"],
        "indicators": [
            r"redirect_uri=", r"SAMLResponse", r"response_type=token",
            r"id_token", r"response_type=code%20token|implicit",
            r"state=\s*(?:&|$)",                 # missing/empty state (CSRF surface)
            r"\"iss\"\s*:|\"aud\"\s*:", r"AssertionConsumerServiceURL",
            r"access_token=[A-Za-z0-9._-]+(?:&|$)",  # token leaked in URL
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "http_request_smuggling": {
        "cwe": "CWE-444", "mitre": ["T1190"],
        "indicators": [
            r"Transfer-Encoding:\s*chunked", r"Content-Length:.*Transfer-Encoding",
            r"Transfer-Encoding:[^\r\n]*[\x0b\x0c\t ]chunked",  # TE obfuscation
            r"(?:Content-Length[^\r\n]*\r\n){2,}",              # duplicate CL
            r"400 Bad Request.*(invalid|malformed) (chunk|header)",
        ],
        "references": ["https://portswigger.net/web-security/request-smuggling"],
    },
    "security_misconfiguration": {
        "cwe": "CWE-16", "mitre": ["T1190"],
        "indicators": [
            r"Index of /", r"phpinfo\(\)", r"debug\s*=\s*true",
            r"\bAPP_DEBUG\s*=\s*true|DEBUG\s*=\s*True",
            r"<title>phpMyAdmin|/server-status|/actuator(/|$)|/manager/html",
            r"X-Debug-Token|Symfony Profiler|Spring Boot Actuator",
            r"directory listing|autoindex", r"\.(bak|old|swp|orig|save)\b",
        ],
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
