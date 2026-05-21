"""Unit tests for the index circuit breaker."""

from __future__ import annotations

import pytest

from provenex.index.circuit import (
    STATE_CLOSED,
    STATE_HALF_OPEN,
    STATE_OPEN,
    CircuitBreaker,
)


class FakeClock:
    """Monotonic-style fake clock the test drives by hand."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_breaker(clock: FakeClock, *, threshold: int = 3) -> CircuitBreaker:
    return CircuitBreaker(
        threshold=threshold,
        window_seconds=10.0,
        cooldown_seconds=5.0,
        clock=clock,
    )


def test_starts_closed_and_allows():
    clock = FakeClock()
    b = make_breaker(clock)
    assert b.state == STATE_CLOSED
    assert b.allow() is True


def test_trips_open_after_threshold_failures_in_window():
    clock = FakeClock()
    b = make_breaker(clock, threshold=3)
    b.record_failure()
    b.record_failure()
    assert b.state == STATE_CLOSED
    b.record_failure()
    assert b.state == STATE_OPEN
    assert b.allow() is False


def test_failures_outside_window_do_not_trip():
    clock = FakeClock()
    b = make_breaker(clock, threshold=3)
    b.record_failure()
    b.record_failure()
    # Skip past the window so old failures are pruned before the third.
    clock.advance(11.0)
    b.record_failure()
    assert b.state == STATE_CLOSED


def test_half_open_admits_one_probe_then_blocks():
    clock = FakeClock()
    b = make_breaker(clock, threshold=2)
    b.record_failure()
    b.record_failure()
    assert b.state == STATE_OPEN
    clock.advance(6.0)  # past cooldown
    assert b.allow() is True
    assert b.state == STATE_HALF_OPEN
    # No second probe until the first reports its outcome.
    assert b.allow() is False


def test_half_open_success_closes_breaker_and_clears_failures():
    clock = FakeClock()
    b = make_breaker(clock, threshold=2)
    b.record_failure()
    b.record_failure()
    clock.advance(6.0)
    assert b.allow() is True  # probe
    b.record_success()
    assert b.state == STATE_CLOSED
    assert b.allow() is True
    # The breaker's old failure history is cleared, so another single
    # failure does NOT immediately trip again.
    b.record_failure()
    assert b.state == STATE_CLOSED


def test_half_open_failure_re_opens_breaker():
    clock = FakeClock()
    b = make_breaker(clock, threshold=2)
    b.record_failure()
    b.record_failure()
    clock.advance(6.0)
    assert b.allow() is True  # probe
    b.record_failure()
    assert b.state == STATE_OPEN
    assert b.allow() is False


def test_threshold_validation():
    with pytest.raises(ValueError):
        CircuitBreaker(threshold=0)
    with pytest.raises(ValueError):
        CircuitBreaker(window_seconds=0)
    with pytest.raises(ValueError):
        CircuitBreaker(cooldown_seconds=-1)
