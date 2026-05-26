"""End-to-end Datadog Logs ingestion smoke test for Provenex receipts.

Run against the Datadog Logs intake::

    export PROVENEX_RECEIPT_PRIVATE_KEY_PATH=keys/private.pem
    export PROVENEX_INDEX_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    export DD_API_KEY=00000000000000000000000000000000
    export DD_SITE=datadoghq.com   # or datadoghq.eu, us3.datadoghq.com, etc.
    python examples/datadog_logs_ingest.py

What it does, in order:

    1. Produce one VERIFIED retrieval receipt and one tool-call deny
       receipt against an in-memory index. Both are Ed25519-signed.

    2. POST each receipt to the Datadog Logs HTTP intake at
       ``https://http-intake.logs.<site>/api/v2/logs`` with
       ``ddsource=provenex`` so the Provenex pipeline picks the events
       up and applies the parsing rules in ``siem/datadog/pipeline.json``.

    3. Wait briefly, then print the Logs Explorer search expression the
       SOC analyst can paste into Datadog to confirm ingestion.

If ``DD_API_KEY`` is unset, the script generates receipts and dumps
the intake-shaped payload to stdout -- a useful offline rehearsal
that exercises the receipt + envelope shaping without needing a live
Datadog tenant.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

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


class _Doc:
    def __init__(self, page_content: str, metadata: Dict[str, Any] = None) -> None:
        self.page_content = page_content
        self.metadata = metadata or {}


_TOOL_POLICY_YAML = """
version: 1
policy_id: datadog-logs-smoke-v1
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
        purpose="datadog_logs_smoke_test",
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
    assert tool_call.decision == "deny"

    return [retrieval.receipt.to_dict(), tool_call.receipt.to_dict()]


def _envelope(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Wrap a receipt in the Datadog Logs intake envelope.

    The envelope sets ``ddsource`` and ``service`` so the Provenex log
    pipeline (``filter: source:provenex``) matches and applies the
    processors in ``siem/datadog/pipeline.json``.
    """
    host = os.uname().nodename if hasattr(os, "uname") else "provenex-host"
    sourcetype = (
        "provenex.drift"
        if receipt.get("type") == "provenex.index_drift"
        else "provenex.receipt"
    )
    return {
        "ddsource": "provenex",
        "ddtags": f"env:dev,service:{sourcetype}",
        "service": sourcetype,
        "hostname": host,
        "message": json.dumps(receipt),
    }


def _post_to_datadog(payloads: List[Dict[str, Any]], site: str, api_key: str) -> None:
    try:
        import requests  # type: ignore[import-not-found]
    except ImportError:
        print(
            "error: the `requests` library is needed to talk to Datadog. "
            "Install with `pip install requests`.",
            file=sys.stderr,
        )
        sys.exit(2)

    url = f"https://http-intake.logs.{site}/api/v2/logs"
    headers = {
        "DD-API-KEY": api_key,
        "Content-Type": "application/json",
    }
    resp = requests.post(url, headers=headers, json=payloads, timeout=30)
    if resp.status_code >= 300:
        print(
            f"error: Datadog intake returned {resp.status_code}: {resp.text}",
            file=sys.stderr,
        )
        sys.exit(2)
    print(f"posted {len(payloads)} receipts to {url} (status {resp.status_code})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()

    receipts = _produce_receipts()
    print(
        f"produced {len(receipts)} receipts (receipt_ids="
        f"{[r['receipt_id'] for r in receipts]})"
    )

    api_key = os.environ.get("DD_API_KEY")
    site = os.environ.get("DD_SITE", "datadoghq.com")
    payloads = [_envelope(r) for r in receipts]

    if not api_key:
        print(
            "DD_API_KEY not set. Dumping the intake-shaped payloads to stdout "
            "so you can pipe them into Datadog manually:"
        )
        for p in payloads:
            print(json.dumps(p))
        return 0

    _post_to_datadog(payloads, site, api_key)
    receipt_ids = " OR ".join(f'@receipt_id:"{r["receipt_id"]}"' for r in receipts)
    print(
        "\nVerify in Datadog Logs Explorer:\n"
        f"  source:provenex service:provenex.receipt ({receipt_ids})"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
