"""
penetration_testing.execution.executor
=======================================

Runs a single :class:`~penetration_testing.models.Task` through the module
bridge under strict bounds, and manages task lifecycle/state transitions.

Consolidates the directive's ``executor`` / ``tool_manager`` /
``timeout_manager`` / ``output_collector`` / ``execution_monitor`` /
``execution_policy`` / ``resource_manager`` concerns.

Guarantees
----------
* **Timeout bound.** Each task runs in a worker thread and is awaited with a
  wall-clock timeout. Honest limitation: the existing ARTEX modules are
  synchronous and not cancellable mid-call, so a timeout stops *us waiting* and
  moves on; the worker is a daemon thread and cannot block process shutdown. It
  does not forcibly kill in-flight socket work inside the delegated module.
* **Security denials are never retried.** ``ScopeViolation`` / ``PermissionDenied``
  / ``RateLimitExceeded`` mark the task ``DENIED`` immediately.
* **Bounded retries.** Only ``retryable`` errors are retried, up to ``max_retries``
  with linear backoff.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Optional

from ..constants import TaskState
from ..exceptions import (
    ExecutionCancelled,
    ExecutionTimeout,
    PenTestError,
    SecurityPolicyError,
)
from ..integration.module_bridge import ModuleBridge
from ..models import Target, Task, ToolResult


class Executor:
    def __init__(
        self,
        bridge: ModuleBridge,
        *,
        task_timeout: int = 180,
        max_retries: int = 1,
        logger: Optional[logging.Logger] = None,
    ):
        self.bridge = bridge
        self.task_timeout = task_timeout
        self.max_retries = max_retries
        self.logger = logger or logging.getLogger(__name__)
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def execute(self, task: Task, target: Target) -> ToolResult:
        if self._cancelled:
            task.state = TaskState.CANCELLED
            raise ExecutionCancelled("Engagement cancelled before task start.")

        task.state = TaskState.RUNNING
        task.started_at = time.time()
        attempt = 0
        last_error: Optional[PenTestError] = None

        while attempt <= self.max_retries:
            attempt += 1
            task.attempts = attempt
            try:
                result = self._run_with_timeout(task, target)
                task.result = result.data
                task.state = TaskState.COMPLETED
                task.finished_at = time.time()
                return result
            except SecurityPolicyError as exc:
                # Policy denial — never retry, mark denied and stop.
                task.state = TaskState.DENIED
                task.error = str(exc)
                task.finished_at = time.time()
                self.logger.warning("Task %s denied: %s", task.capability, exc)
                return ToolResult(ok=False, capability=task.capability, error=str(exc))
            except ExecutionCancelled:
                task.state = TaskState.CANCELLED
                task.finished_at = time.time()
                raise
            except PenTestError as exc:
                last_error = exc
                if not exc.retryable or attempt > self.max_retries:
                    break
                backoff = 1.5 * attempt
                self.logger.info("Retrying %s after error (%s); backoff %.1fs",
                                 task.capability, exc, backoff)
                time.sleep(backoff)

        task.state = TaskState.FAILED
        task.error = str(last_error) if last_error else "unknown error"
        task.finished_at = time.time()
        return ToolResult(ok=False, capability=task.capability, error=task.error)

    def _run_with_timeout(self, task: Task, target: Target) -> ToolResult:
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="pt-exec") as pool:
            future = pool.submit(self.bridge.invoke, task.capability, target,
                                 task.params, task.task_id)
            try:
                return future.result(timeout=self.task_timeout)
            except FuturesTimeout as exc:
                # We stop waiting; the daemon worker may still be finishing.
                raise ExecutionTimeout(
                    f"Task '{task.capability}' exceeded {self.task_timeout}s.",
                ) from exc
