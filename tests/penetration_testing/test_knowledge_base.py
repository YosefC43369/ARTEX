from penetration_testing.constants import VulnCategory
from penetration_testing.intelligence.knowledge_base import KnowledgeBase
from penetration_testing.models import Finding


def test_loads_entries():
    kb = KnowledgeBase()
    assert len(kb) >= 4
    entry = kb.for_category("tls_weakness")
    assert entry is not None and entry.remediation


def test_search_ranks_relevant():
    kb = KnowledgeBase()
    results = kb.search("expired tls certificate cipher")
    assert results
    assert results[0].category == "tls_weakness"


def test_search_empty_query():
    assert KnowledgeBase().search("") == []


def test_enrich_fills_missing_remediation_and_references():
    kb = KnowledgeBase()
    f = Finding(target_id="t1", category=VulnCategory.MISSING_HEADERS,
                title="Missing headers", description="d")  # no remediation/refs
    kb.enrich(f)
    assert f.remediation            # filled from KB
    assert f.references             # filled from KB


def test_enrich_does_not_overwrite():
    kb = KnowledgeBase()
    f = Finding(target_id="t1", category=VulnCategory.TLS_WEAKNESS,
                title="x", description="d", remediation="CUSTOM", references=["r"])
    kb.enrich(f)
    assert f.remediation == "CUSTOM"
    assert f.references == ["r"]
