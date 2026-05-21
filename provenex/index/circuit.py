"""Circuit breaker for the provenance-index hot path.

The provenance index is the only network dependency on the verify
hot path. When it slows down or stops answering, the server has two
problems to solve:

    1. Do not pile up requests against a struggling backend. Holding
       open verify calls multiplies the load and ultimately exhausts
       the connection pool.
    2. Decide, fast, what to do for callers that came after the
       backend failed: refuse cleanly (fail-closed) or issue a
       receipt that says "we could not verify right now"
       (fail-open with a degraded receipt). The mode is configured
       in :class:`~provenex.policy.availability.IndexAvailabilityPolicy`.

This module supplies the first half. The breaker tracks failures
over a sliding window and, on enough failures, OPENs. While OPEN,
:meth:`CircuitBreaker.allow` returns False without going near the
index. After a cooldown the breaker moves to HALF_OPEN and admits
one probe call. The probe's outcome decides whether to CLOSE
(success) or re-OPEN (failure).

State is kept in process. A multi-replica deployment has one breaker
per replica, by design: a breaker informed by one replica's pool
health should not freeze a healthy replica.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Deque

STATE_CLOSED = "closed"
STATE_OPEN = "open"
STATE_HALF_OPEN = "half_open"


class CircuitBreaker:
    """Sliding-window error counter with an OPEN / HALF_OPEN / CLOSED state machine.

    A failure is anything the caller reports via :meth:`record_failure` —
    timeout, connection error, pool exhaustion, application-level error.
    The breaker does not interpret the failure; it counts.

    Thread-safe via an internal :class:`threading.Lock`. The lock is held
    only for fast in-memory bookkeeping (no I/O), so it is safe to call
    from both sync threads and async event loops.

    Args:
        threshold: Number of failures within the window that trips OPEN.
        window_seconds: Sliding-window length for failure counting.
        cooldown_seconds: How long OPEN stays before allowing a HALF_OPEN
            probe.
        clock: Monotonic clock function. Override only in tests.
    """

    def __init__(
        self,
        *,
        threshold: int = 5,
        window_seconds: float = 30.0,
        cooldown_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if threshold < 1:
            raise ValueError(f"threshold must be >= 1, got {threshold}")
        if window_seconds <= 0:
            raise ValueError(
                f"window_seconds must be > 0, got {window_seconds}"
            )
        if cooldown_seconds <= 0:
            raise ValueError(
                f"cooldown_seconds must be > 0, got {cooldown_seconds}"
            )
        self._threshold = threshold
        self._window = window_seconds
        self._cooldown = cooldown_seconds
        self._clock = clock
        self._lock = threading.Lock()
        # Cap the deque at the trip threshold. Once we have `threshold`
        # entries inside the window the breaker is already tripping; any
        # additional failure beyond that is redundant for the decision
        # and would just consume memory. ``deque(maxlen=threshold)``
        # evicts the oldest on overflow, which preserves the sliding-
        # window semantics (the oldest entry is also the one
        # ``_prune_locked`` would drop next).
        self._failures: Deque[float] = deque(maxlen=threshold)
        self._state = STATE_CLOSED
        self._open_until: float = 0.0
        self._probe_in_flight = False

    @property
    def state(self) -> str:
        """Current state: ``"closed"``, ``"open"``, or ``"half_open"``.

        The property is point-in-time. The state may transition between
        reads under concurrent traffic; use :meth:`allow` to make the
        decision atomically with the transition.
        """
        with self._lock:
            return self._evaluate_state_locked()

    def allow(self) -> bool:
        """Decide whether to admit one call through the breaker.

        Returns:
            ``True`` if the caller should proceed to the index;
            ``False`` if the breaker is OPEN and the call should be
            short-circuited. In HALF_OPEN, exactly one concurrent
            caller gets ``True`` (the probe); others see ``False``
            until the probe reports its outcome.
        """
        with self._lock:
            state = self._evaluate_state_locked()
            if state == STATE_CLOSED:
                return True
            if state == STATE_OPEN:
                return False
            if state == STATE_HALF_OPEN:
                if self._probe_in_flight:
                    return False
                self._probe_in_flight = True
                return True
            return False  # pragma: no cover — unreachable

    def record_success(self) -> None:
        """Record a successful index call.

        In CLOSED, this is a no-op (the failure window already prunes
        old timestamps lazily). In HALF_OPEN, a success transitions
        the breaker back to CLOSED and clears the failure history —
        the backend is healthy again.
        """
        with self._lock:
            if self._state == STATE_HALF_OPEN:
                self._state = STATE_CLOSED
                self._failures.clear()
                self._probe_in_flight = False

    def record_failure(self) -> None:
        """Record a failed index call.

        Appends the failure to the sliding window. If the window now
        contains ``threshold`` or more failures, the breaker trips
        OPEN and stays there for ``cooldown_seconds``. A failure
        recorded in HALF_OPEN immediately re-OPENs.
        """
        with self._lock:
            now = self._clock()
            self._failures.append(now)
            self._prune_locked(now)
            if self._state == STATE_HALF_OPEN:
                self._open_locked(now)
                self._probe_in_flight = False
            elif len(self._failures) >= self._threshold:
                self._open_locked(now)

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self._window
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()

    def _open_locked(self, now: float) -> None:
        self._state = STATE_OPEN
        self._open_until = now + self._cooldown

    def _evaluate_state_locked(self) -> str:
        if self._state != STATE_OPEN:
            return self._state
        if self._clock() >= self._open_until:
            self._state = STATE_HALF_OPEN
            self._probe_in_flight = False
        return self._state
