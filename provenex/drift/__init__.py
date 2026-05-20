"""Real-time index-drift detection.

Watches the verify hot path for ``UNVERIFIED`` outcomes and fires a
coalesced webhook when distinct unverified fingerprints accumulate
within a sliding window. Off by default; opt in by wiring the
:class:`IndexDriftDetector` into the server (or any custom verify
wrapper).

The detector is intentionally simple: a thread-safe sliding window,
deduplicated by fingerprint, with a single HTTP POST per flush. It
does not classify drift causes (re-ingest gap, supersession leak,
hostile insertion); that's the operator's call once the alert lands.
"""

from .detector import DriftEvent, IndexDriftDetector

__all__ = ["DriftEvent", "IndexDriftDetector"]
