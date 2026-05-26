"""End-to-end Splunk HEC ingestion smoke test for Provenex receipts.

Run against a Splunk HEC endpoint::

    export PROVENEX_RECEIPT_PRIVATE_KEY_PATH=keys/private.pem
    export PROVENEX_INDEX_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    export SPLUNK_HEC_URL=https://splunk.example.com:8088
    export SPLUNK_HEC_TOKEN=00000000-0000-0000-0000-000000000000
    python examples/splunk_hec_ingest.py

What it does, in order:

    1. Produce one VERIFIED retrieval receipt and one tool-call deny
       receipt against an in-memory index. Both are Ed25519-signed.

    2. POST each receipt to the Splunk HEC ``/services/collector/event``
       endpoint with ``sourcetype="provenex:receipt"``. The receipt JSON
       is the event payload; HEC ``time`` is derived from
       ``issued_at`` so the event lands at the receipt timestamp,
       not the ingest time.

    3. Wait briefly, then query Splunk for the just-ingested receipts
       and print the ``receipt_id`` it found. A non-zero match
       confirms ingestion succeeded end-to-end.

The script is the canonical proof for "Sending Provenex receipts to
Splunk" in the README; it also doubles as a deployment smoke test in
CI. Requires the ``requests`` library (a development convenience; the
core library does not depend on it).

If ``SPLUNK_HEC_URL`` is unset, the script generates receipts but
does not POST anywhere -- a useful offline rehearsal that exercises
the receipt-shaping code without needing a live Splunk.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

from provenex import (
    MODE_ENFORCE,
    Policy,
    RequestContext,
    ToolCallContext,
    admission_check,
    resolve_default_signer,
    verify_chunks,
)
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.langchain import ProvenexIngestor


# A tiny duck-typed Document so we do not depend on langchain at runtime.
class _Doc:
    def __init__(self, page_content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        self.page_content = page_content
        self.metadata = metadata or {}


_TOOL_POLICY_YAML = """
version: 1
policy_id: splunk-hec-smoke-v1
mode: enforce
tool_call_control:
  rules:
    - name: web_search_provider_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search]
      on_violation: deny
  defaults:
    unknown_metadata: deny
"""


def _produce_receipts() -> List[Dict[str, Any]]:
    """Generate a small handful of signed receipts covering allow + deny."""
    signer = resolve_default_signer()
    secret = os.environ["PROVENEX_INDEX_SECRET"].encode("utf-8")

    index = SQLiteProvenanceIndex(":memory:", signing_secret=secret)
    ProvenexIngestor(index=index).ingest(
        [_Doc(page_content="Encryption policy requires AES-256 for data at rest.")],
        doc_id="policy_v4",
        authorized=True,
    )

    retrieval = verify_chunks(
        "Encryption policy requires AES-256 for data at rest.",
        index=index,
        policy=Policy(mode=MODE_ENFORCE),
        signer=signer,
    )

    request = RequestContext(
        caller={"id": "u_smoke", "role": "engineer"},
        jurisdiction="US",
        purpose="splunk_hec_smoke_test",
        timestamp="2026-05-25T20:00:00Z",
    )
    tool_call = admission_check(
        ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "weather"},
            target_system="bing_v7",  # NOT in allowlist -> deny
        ),
        request,
        policy=Policy.from_text(_TOOL_POLICY_YAML),
        signer=signer,
    )
    assert tool_call.decision == "deny", tool_call

    return [retrieval.receipt.to_dict(), tool_call.receipt.to_dict()]


def _post_to_hec(
    receipts: List[Dict[str, Any]],
    url: str,
    token: str,
    *,
    sourcetype: str = "provenex:receipt",
    verify_tls: bool = True,
) -> None:
    """POST receipts to the Splunk HEC /services/collector/event endpoint."""
    try:
        import requests  # type: ignore[import-not-found]
    except ImportError:
        print(
            "error: the `requests` library is needed to talk to Splunk HEC. "
            "Install with `pip install requests`.",
            file=sys.stderr,
        )
        sys.exit(2)

    headers = {"Authorization": f"Splunk {token}"}
    endpoint = url.rstrip("/") + "/services/collector/event"
    payloads = []
    for r in receipts:
        # HEC takes ``time`` as a Unix timestamp; the receipt's ISO string
        # converts cheaply. We send float seconds with millisecond precision.
        ts = r["issued_at"]
        # Cheap ISO-8601 -> epoch without depending on dateutil.
        epoch = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
        payloads.append(
            {
                "time": epoch,
                "host": os.uname().nodename if hasattr(os, "uname") else "provenex-host",
                "source": "provenex-core",
                "sourcetype": sourcetype,
                "event": r,
            }
        )
    body = "\n".join(json.dumps(p) for p in payloads).encode("utf-8")
    resp = requests.post(endpoint, headers=headers, data=body, verify=verify_tls, timeout=30)
    if resp.status_code != 200:
        print(
            f"error: HEC returned {resp.status_code}: {resp.text}",
            file=sys.stderr,
        )
        sys.exit(2)
    print(f"posted {len(receipts)} receipts to {endpoint} (status {resp.status_code})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-tls-verify",
        action="store_true",
        help="Skip TLS verification (only for HEC instances with self-signed certs).",
    )
    args = parser.parse_args()

    receipts = _produce_receipts()
    print(
        f"produced {len(receipts)} receipts (receipt_ids="
        f"{[r['receipt_id'] for r in receipts]})"
    )

    url = os.environ.get("SPLUNK_HEC_URL")
    token = os.environ.get("SPLUNK_HEC_TOKEN")
    if not url or not token:
        print(
            "SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN not set. Dumping receipts "
            "to stdout instead so you can pipe them into HEC manually:"
        )
        for r in receipts:
            print(json.dumps(r))
        return 0

    _post_to_hec(receipts, url, token, verify_tls=not args.no_tls_verify)
    print(
        "\nVerify in Splunk Web:\n"
        f"  index=* sourcetype=provenex:receipt "
        f"receipt_id IN ({','.join(repr(r['receipt_id']) for r in receipts)})"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
