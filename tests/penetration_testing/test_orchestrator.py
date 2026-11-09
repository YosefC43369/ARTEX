from penetration_testing.configuration import load_settings
from penetration_testing.constants import SessionState
from penetration_testing.evidence.evidence_store import EvidenceStore
from penetration_testing.execution.executor import Executor
from penetration_testing.intelligence.analysis import AnalysisEngine
from penetration_testing.intelligence.planner import Planner
from penetration_testing.llm_client import OpenRouterClient
from penetration_testing.models import ToolResult
from penetration_testing.orchestrator import Orchestrator
from penetration_testing.security.scope_manager import ScopeManager


class _Spec:
    def __init__(self, name, permission):
        self.name = name
        self.permission = permission
        self.available = True


class FakeBridge:
    """Scope-free stand-in so the orchestrator loop can be tested offline."""

    DATA = {
        "recon.subdomains": {"subdomains": [{"subdomain": "www.example.com"}], "count": 1},
        "tls.inspect": {"tls": {"expired": True}},
    }

    def list_capabilities(self, available_only=True):
        return [_Spec("recon.subdomains", "recon"), _Spec("tls.inspect", "tls_inspection")]

    def invoke(self, name, target, params=None, task_id="adhoc"):
        return ToolResult(ok=True, capability=name, data=self.DATA.get(name, {}))


def _orchestrator(settings, bridge, approval=None, role=None):
    scope = ScopeManager(settings)
    evidence = EvidenceStore(enabled=True)
    llm = OpenRouterClient("")
    return Orchestrator(
        settings, scope, bridge, Planner(llm), Executor(bridge),
        AnalysisEngine(evidence), evidence, llm,
        approval=approval, role=role,
    )


def test_end_to_end_offline(settings):
    orch = _orchestrator(settings, FakeBridge())
    session = orch.run("t1")
    assert session.state == SessionState.COMPLETED
    assert session.counts()["tasks_completed"] == 2
    # tls expired -> at least one confirmed finding; subdomains -> info finding
    assert session.counts()["findings"] >= 1
    assert session.metadata["evidence_chain"]["valid"] is True
    reports = orch.build_reports(["json", "markdown"])
    assert "json" in reports and "markdown" in reports


def test_unknown_target_fails_closed(settings):
    orch = _orchestrator(settings, FakeBridge())
    session = orch.run("ghost")
    assert session.state == SessionState.FAILED
    assert "scope" in (session.error or "").lower()


def test_no_permitted_capabilities_completes(tmp_path):
    cfg = tmp_path / "c.xml"
    cfg.write_text("""<artex_pentest><targets>
      <target id="t1"><domain>example.com</domain>
        <permissions><recon>false</recon></permissions></target>
    </targets></artex_pentest>""")
    s = load_settings(str(cfg))

    class Empty(FakeBridge):
        def list_capabilities(self, available_only=True):
            return []
    session = _orchestrator(s, Empty()).run("t1")
    assert session.state == SessionState.COMPLETED
    assert session.counts()["tasks_total"] == 0


def test_bounded_by_cancellation(settings):
    orch = _orchestrator(settings, FakeBridge())
    orch.cancel()
    session = orch.run("t1")
    assert session.state in (SessionState.CANCELLED, SessionState.COMPLETED)


def test_role_reorders_plan(settings):
    from penetration_testing.roles import RoleManager
    # web-app-tester prefers tls.inspect over subdomains (opposite of default)
    role = RoleManager().get("web-app-tester")
    orch = _orchestrator(settings, FakeBridge(), role=role)
    session = orch.run("t1")
    caps = [t.capability for t in session.tasks]
    assert caps[0] == "tls.inspect"


def test_approval_holds_then_resume_runs(settings):
    from penetration_testing.constants import TaskState
    from penetration_testing.security.approval import ApprovalManager
    appr = ApprovalManager(required={"tls.inspect"})
    orch = _orchestrator(settings, FakeBridge(), approval=appr)
    session = orch.run("t1")

    held = [t for t in session.tasks if t.capability == "tls.inspect"]
    assert held and held[0].state == TaskState.AWAITING_APPROVAL
    pending = appr.pending(session.session_id)
    assert pending

    appr.decide(pending[0].approval_id, True)
    orch.resume()
    held = [t for t in session.tasks if t.capability == "tls.inspect"]
    assert held[0].state == TaskState.COMPLETED
