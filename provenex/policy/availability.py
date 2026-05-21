"""Operator-controlled behavior when the provenance index is unreachable.

The provenance index is the one network dependency on the verify hot
path. This module supplies the config knob that decides what happens
when a lookup against it fails — timeout, connection error, pool
exhaustion, circuit breaker open — and the exception type the verify
path raises when the operator chose to fail closed.

Two modes are supported in this release:

* ``"block"`` (default, fail-closed). The verify call raises
  :class:`IndexUnavailable`. The HTTP server maps that to 503. The
  caller knows the receipt was not produced and decides what to do
  next. Recommended for any deployment where a receipt that says
  ``VERIFIED`` must mean the index was consulted.

* ``"degrade"`` (fail-open with a degraded receipt). The verify call
  returns a signed receipt where every chunk's outcome is
  ``UNVERIFIED`` and the top-level ``index_status`` block records the
  error. The receipt is still cryptographically valid; the auditor
  reading it sees an explicit "we could not consult the index at
  this moment" rather than ambiguous misses. Recommended for
  read-mostly workloads where the agent must keep moving and the
  receipt's role is the audit trail, not the gate.

A third mode (``"cache_only"``) is reserved for a future release;
acceptance criteria and cache freshness semantics need their own
design pass.
"""

from __future__ import annotations

from dataclasses import dataclass

ON_ERROR_BLOCK = "block"
ON_ERROR_DEGRADE = "degrade"
_VALID_ON_ERROR = (ON_ERROR_BLOCK, ON_ERROR_DEGRADE)


@dataclass(frozen=True)
class IndexAvailabilityPolicy:
    """How the verify path behaves when the index is unreachable.

    Attributes:
        on_index_error: One of ``"block"`` or ``"degrade"``. ``"block"``
            (default) raises :class:`IndexUnavailable`. ``"degrade"``
            issues a signed receipt with every outcome forced to
            ``UNVERIFIED`` and the top-level ``index_status`` block set.
        timeout_seconds: Per-call timeout on the index round-trip
            (async path only). Sync callers should set their database
            driver's statement timeout instead. ``None`` disables the
            wrapper timeout.
        breaker_threshold: Failures within ``breaker_window_seconds``
            that trip the circuit breaker to OPEN.
        breaker_window_seconds: Sliding-window length for the breaker's
            failure counter.
        breaker_cooldown_seconds: How long the breaker stays OPEN
            before admitting a HALF_OPEN probe.
    """

    on_index_error: str = ON_ERROR_BLOCK
    timeout_seconds: float | None = 2.0
    breaker_threshold: int = 5
    breaker_window_seconds: float = 30.0
    breaker_cooldown_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.on_index_error not in _VALID_ON_ERROR:
            raise ValueError(
                f"IndexAvailabilityPolicy: on_index_error must be one of "
                f"{list(_VALID_ON_ERROR)!r}, got {self.on_index_error!r}"
            )
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError(
                f"IndexAvailabilityPolicy: timeout_seconds must be > 0 "
                f"or None, got {self.timeout_seconds!r}"
            )
        if self.breaker_threshold < 1:
            raise ValueError(
                f"IndexAvailabilityPolicy: breaker_threshold must be >= 1, "
                f"got {self.breaker_threshold!r}"
            )
        if self.breaker_window_seconds <= 0:
            raise ValueError(
                f"IndexAvailabilityPolicy: breaker_window_seconds must be "
                f"> 0, got {self.breaker_window_seconds!r}"
            )
        if self.breaker_cooldown_seconds <= 0:
            raise ValueError(
                f"IndexAvailabilityPolicy: breaker_cooldown_seconds must "
                f"be > 0, got {self.breaker_cooldown_seconds!r}"
            )


class IndexUnavailable(Exception):
    """Raised by the verify path when the index cannot serve a request
    and the operator chose ``on_index_error="block"``.

    Attributes:
        error_class: One of ``"timeout"``, ``"connection"``,
            ``"breaker_open"``, or ``"other"``. Recorded on the
            exception so the HTTP handler / metrics layer can label
            the cause without parsing the message string.
    """

    def __init__(self, message: str, *, error_class: str) -> None:
        super().__init__(message)
        self.error_class = error_class
