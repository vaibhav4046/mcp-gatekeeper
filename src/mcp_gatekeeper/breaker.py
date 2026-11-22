"""Per-session circuit breaker. Pure bookkeeping: the proxy decides what to do on a trip.

The proxy only calls it while holding the session's asyncio.Lock, so counters are never
updated concurrently; there are no awaits inside these methods.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable

from .config import Limits


class CircuitBreaker:
    def __init__(self, limits: Limits, clock: Callable[[], float] = time.monotonic) -> None:
        self._l = limits
        self._clock = clock
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self.violations = 0
        self.writes = 0
        self.tripped: str | None = None

    def _trip(self, reason: str) -> str:
        self.tripped = self.tripped or reason
        return self.tripped

    def record_failure(self, fingerprint: str) -> str | None:
        """A query failed (DB error, conflict, invariant). Returns a trip reason or None."""
        now = self._clock()
        window = self._failures[fingerprint]
        window.append(now)
        while window and now - window[0] > self._l.failure_window_s:
            window.popleft()
        if len(window) > self._l.max_identical_failures:
            return self._trip(f"REPEATED_FAILURE: same query failed {len(window)} times in {self._l.failure_window_s:.0f}s")
        return None

    def record_violation(self) -> str | None:
        self.violations += 1
        if self.violations >= self._l.max_policy_violations:
            return self._trip(f"POLICY_VIOLATIONS: {self.violations} refused statements in this session")
        return None

    def record_write(self) -> str | None:
        """Call before executing a write. The write that would exceed the cap is refused."""
        self.writes += 1
        if self.writes > self._l.max_writes:
            return self._trip(f"WRITE_LIMIT: write #{self.writes} exceeds the cap of {self._l.max_writes}")
        return None
