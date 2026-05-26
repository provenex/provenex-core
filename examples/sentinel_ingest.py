"""End-to-end Microsoft Sentinel ingestion smoke test for Provenex receipts.

Run against an Azure Log Analytics workspace via the HTTP Data Collector API::

    export PROVENEX_RECEIPT_PRIVATE_KEY_PATH=keys/private.pem
    export PROVENEX_INDEX_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    export AZURE_LAW_WORKSPACE_ID=00000000-0000-0000-0000-000000000000
    export AZURE_LAW_SHARED_KEY=...                  # primary or secondary key
    python examples/sentinel_ingest.py

What it does, in order:

    1. Produce one VERIFIED retrieval receipt and one tool-call deny
       receipt against an in-memory index. Both are Ed25519-signed.

    2. POST each receipt to the Log Analytics HTTP Data Collector API
       at ``https://<workspace>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01``
       with ``Log-Type: Provenex_Receipt``. Sentinel auto-appends ``_CL``
       so the table the KQL queries scan is ``Provenex_Receipt_CL``.

    3. Print the Sentinel/Log Analytics query the SOC analyst can paste
       to confirm ingestion. Note: rows may take a few minutes to surface
       in the workspace -- this is Sentinel's normal ingestion latency.

If ``AZURE_LAW_WORKSPACE_ID`` is unset, the script generates receipts
and dumps the wire-format payloads to stdout for offline rehearsal.

Note on the API: the HTTP Data Collector API is on a deprecation path
in favor of the Azure Monitor Logs Ingestion API (Entra ID-based, no
shared keys). This script uses the older API because it is the one
with the smallest dependency surface. For production deployments,
prefer the newer API or a managed Logic App / Function forwarder.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
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
policy_id: sentinel-ingest-smoke-v1
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
        purpose="sentinel_ingest_smoke_test",
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


def _build_signature(
    workspace_id: str,
    shared_key: str,
    rfc1123_date: str,
    content_length: int,
    method: str = "POST",
    content_type: str = "application/json",
    resource: str = "/api/logs",
) -> str:
    """Compute the HMAC-SHA256 signature header for the Data Collector API."""
    x_headers = f"x-ms-date:{rfc1123_date}"
    string_to_hash = (
        f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    )
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"


def _post_to_law(
    receipts: List[Dict[str, Any]],
    workspace_id: str,
    shared_key: str,
    *,
    log_type: str = "Provenex_Receipt",
) -> None:
    try:
        import requests  # type: ignore[import-not-found]
    except ImportError:
        print(
            "error: the `requests` library is needed to talk to the Data Collector API. "
            "Install with `pip install requests`.",
            file=sys.stderr,
        )
        sys.exit(2)

    body = json.dumps(receipts).encode("utf-8")
    rfc1123_date = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )
    signature = _build_signature(
        workspace_id=workspace_id,
        shared_key=shared_key,
        rfc1123_date=rfc1123_date,
        content_length=len(body),
    )
    headers = {
        "Content-Type": "application/json",
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123_date,
        "time-generated-field": "issued_at",
    }
    url = (
        f"https://{workspace_id}.ods.opinsights.azure.com"
        f"/api/logs?api-version=2016-04-01"
    )
    resp = requests.post(url, headers=headers, data=body, timeout=30)
    if resp.status_code >= 300:
        print(
            f"error: Sentinel intake returned {resp.status_code}: {resp.text}",
            file=sys.stderr,
        )
        sys.exit(2)
    print(
        f"posted {len(receipts)} receipts to {url} (status {resp.status_code}); "
        f"table {log_type}_CL"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()

    receipts = _produce_receipts()
    print(
        f"produced {len(receipts)} receipts (receipt_ids="
        f"{[r['receipt_id'] for r in receipts]})"
    )

    workspace_id = os.environ.get("AZURE_LAW_WORKSPACE_ID")
    shared_key = os.environ.get("AZURE_LAW_SHARED_KEY")
    if not workspace_id or not shared_key:
        print(
            "AZURE_LAW_WORKSPACE_ID or AZURE_LAW_SHARED_KEY not set. Dumping "
            "receipts to stdout so you can pipe them into the Data Collector "
            "API manually:"
        )
        for r in receipts:
            print(json.dumps(r))
        return 0

    _post_to_law(receipts, workspace_id, shared_key)
    receipt_ids = " or ".join(f'receipt_id_s == "{r["receipt_id"]}"' for r in receipts)
    print(
        "\nVerify in Sentinel / Log Analytics (may take a few minutes to land):\n"
        "  Provenex_Receipt_CL\n"
        f"  | where {receipt_ids}\n"
        "  | project TimeGenerated, receipt_id_s, host_s, caller_hash_s"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
