from penetration_testing.constants import EvidenceKind
from penetration_testing.evidence.evidence_store import EvidenceStore, redact


def _rec(store, summary="x", **data):
    return store.record(target_id="t1", task_id="task1",
                        kind=EvidenceKind.OBSERVATION, summary=summary, data=dict(data))


def test_record_and_fetch(evidence):
    ev = _rec(evidence, a=1)
    assert ev is not None
    assert evidence.get(ev.evidence_id) is ev
    assert evidence.for_task("task1") == [ev]
    assert ev.verify() is True


def test_disabled_store_records_nothing():
    store = EvidenceStore(enabled=False)
    assert _rec(store) is None
    assert store.all() == []


def test_chain_verifies_and_detects_tamper(evidence):
    _rec(evidence, n=1); _rec(evidence, n=2); _rec(evidence, n=3)
    assert evidence.verify_chain()["valid"] is True
    # tamper with the middle record's content
    evidence.all()[1].summary = "TAMPERED"
    result = evidence.verify_chain()
    assert result["valid"] is False
    assert result["broken_at"] == 1


def test_redaction_of_secrets():
    txt = "Authorization: Bearer abc.def.ghi\npassword=hunter2"
    out = redact(txt)
    assert "hunter2" not in out
    assert "abc.def.ghi" not in out or "[REDACTED" in out


def test_request_headers_redacted(evidence):
    ev = evidence.record(
        target_id="t1", task_id="task1", kind=EvidenceKind.HTTP_EXCHANGE,
        summary="req", request={"headers": {"Authorization": "secret",
                                             "Accept": "*/*"}})
    assert ev.request["headers"]["Authorization"] == "[REDACTED]"
    assert ev.request["headers"]["Accept"] == "*/*"
