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
