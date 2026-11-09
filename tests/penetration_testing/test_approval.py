from penetration_testing.security.approval import ApprovalManager


def test_non_gated_capability_is_implicitly_approved():
    am = ApprovalManager(required={"scan.ports"})
    assert am.requires_approval("recon.dns") is False
    assert am.is_approved("s1", "recon.dns") is True


def test_gated_capability_requires_explicit_approval():
    am = ApprovalManager(required={"scan.ports"})
    assert am.requires_approval("scan.ports") is True
    assert am.is_approved("s1", "scan.ports") is False
    appr = am.request("s1", "t1", "scan.ports")
    assert appr.state == "pending"
    # idempotent request returns the same approval
    assert am.request("s1", "t1", "scan.ports").approval_id == appr.approval_id
    am.decide(appr.approval_id, True)
    assert am.is_approved("s1", "scan.ports") is True


def test_reject():
    am = ApprovalManager(required={"scan.ports"})
    appr = am.request("s2", "t1", "scan.ports")
    am.decide(appr.approval_id, False)
    assert am.is_approved("s2", "scan.ports") is False
    assert appr.state == "rejected"


def test_pending_scoping():
    am = ApprovalManager(required={"scan.ports"})
    am.request("sA", "t1", "scan.ports")
    am.request("sB", "t1", "scan.ports")
    assert len(am.pending()) == 2
    assert len(am.pending("sA")) == 1


def test_decide_unknown_returns_none():
    assert ApprovalManager().decide("appr_missing", True) is None
