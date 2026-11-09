from penetration_testing.intelligence.signatures import SignatureLibrary


def test_mapping_has_cwe_and_mitre():
    lib = SignatureLibrary()
    m = lib.mapping("sql_injection")
    assert m["cwe"] == "CWE-89" and m["mitre"]
    assert lib.mapping("ssrf")["cwe"] == "CWE-918"


def test_corroborate_matches_indicators():
    lib = SignatureLibrary()
    assert lib.corroborate("sql_injection",
                           "You have an error in your SQL syntax; MySQL server")
    assert lib.corroborate("ssrf", "fetched 169.254.169.254 iam/security-credentials")
    assert lib.corroborate("graphql_exposure", '{"data":{"__schema":{"queryType":{}}}}')
    assert lib.corroborate("sql_injection", "totally benign response") == []


def test_modern_categories_present():
    cats = set(SignatureLibrary().categories())
    assert {"graphql_exposure", "prototype_pollution", "mass_assignment",
            "oauth_saml_misconfig", "http_request_smuggling"} <= cats


def test_every_vuln_category_maps_to_cwe():
    from penetration_testing.constants import VulnCategory
    lib = SignatureLibrary()
    for cat in VulnCategory:
        assert lib.mapping(cat.value)["cwe"], f"{cat.value} has no CWE"


def test_expanded_indicators_reduce_false_negatives():
    lib = SignatureLibrary()
    # banners/markers added in the signature update must now corroborate
    assert lib.corroborate("sql_injection", "You have an error in your SQL syntax near '1'")
    assert lib.corroborate("ssrf", "GET metadata/instance?api-version=2021-02-01")
    assert lib.corroborate("subdomain_takeover", "There isn't a GitHub Pages site here.")
    assert lib.corroborate("tls_weakness", "negotiated RC4-SHA cipher")
    assert lib.corroborate("information_exposure", "-----BEGIN RSA PRIVATE KEY-----")
    assert lib.corroborate("graphql_exposure", 'Did you mean "user"?')
    # a benign string still matches nothing
    assert lib.corroborate("sql_injection", "ordinary page content") == []
