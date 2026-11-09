import time

from penetration_testing.constants import Phase, TaskState
from penetration_testing.exceptions import PermissionDenied, ToolExecutionError
from penetration_testing.execution.executor import Executor
from penetration_testing.models import Task, ToolResult


class FakeBridge:
    def __init__(self, behavior):
        self.behavior = behavior
        self.calls = 0

    def invoke(self, name, target, params=None, task_id="adhoc"):
        self.calls += 1
        return self.behavior(self.calls)


def _task(cap="recon.dns"):
    return Task(phase=Phase.RECON, capability=cap)


def test_success(target):
    ex = Executor(FakeBridge(lambda n: ToolResult(ok=True, capability="recon.dns",
                                                  data={"x": 1})))
    t = _task()
    res = ex.execute(t, target)
    assert res.ok and t.state == TaskState.COMPLETED and t.result == {"x": 1}


def test_security_denial_not_retried(target):
    def boom(n):
        raise PermissionDenied("nope")
    bridge = FakeBridge(boom)
    ex = Executor(bridge, max_retries=3)
    t = _task()
    res = ex.execute(t, target)
    assert res.ok is False
    assert t.state == TaskState.DENIED
    assert bridge.calls == 1  # never retried


def test_retryable_error_is_retried(target):
    def boom(n):
        raise ToolExecutionError("transient")
    bridge = FakeBridge(boom)
    ex = Executor(bridge, max_retries=1)
    t = _task()
    res = ex.execute(t, target)
    assert res.ok is False
    assert t.state == TaskState.FAILED
    assert bridge.calls == 2  # original + one retry


def test_timeout(target):
    def slow(n):
        time.sleep(0.5)
        return ToolResult(ok=True, capability="recon.dns")
    ex = Executor(FakeBridge(slow), task_timeout=0.1, max_retries=0)
    t = _task()
    res = ex.execute(t, target)
    assert res.ok is False
    assert t.state == TaskState.FAILED


def test_cancellation(target):
    ex = Executor(FakeBridge(lambda n: ToolResult(ok=True, capability="recon.dns")))
    ex.cancel()
    t = _task()
    import pytest
    from penetration_testing.exceptions import ExecutionCancelled
    with pytest.raises(ExecutionCancelled):
        ex.execute(t, target)
