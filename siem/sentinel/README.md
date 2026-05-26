# Provenex Microsoft Sentinel pack

KQL queries, analytics-rule templates, and a starter Workbook for ingesting Provenex provenance receipts into Microsoft Sentinel. Compatible with provenex-core 1.0.0 (receipt schema 2.6.0+).

## What's inside

```
siem/sentinel/
├── workbook.json                       # Sentinel Workbook (7-panel dashboard)
├── kql/
│   ├── denied_tool_calls.kql           # 24h admission denials
│   ├── unverified_by_jurisdiction.kql  # UNVERIFIED by jurisdiction
│   ├── drift_alerts.kql                # coalesced drift events
│   ├── receipts_by_mode.kql            # v1.0.0+ fleet posture audit
│   └── advisory_would_have_blocked.kql # v1.0.0+ rollout signal
└── analytics_rules/
    ├── tampered_alarms.json            # High: any TAMPERED in 15m
    ├── unverified_spike.json           # Medium: >100 UNVERIFIED per hour
    └── tool_call_deny_burst.json       # High: >20 denies per caller in 30m
```

## Send receipts to Sentinel

Receipts arrive in a Sentinel-attached Log Analytics workspace via:

1. **HTTP Data Collector API (legacy, simplest)**: POST receipts directly to `https://<workspace-id>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01` with `Log-Type: Provenex_Receipt`. Sentinel auto-appends `_CL`, so the table the KQL queries scan is `Provenex_Receipt_CL`. The end-to-end smoke test in [`examples/sentinel_ingest.py`](../../examples/sentinel_ingest.py) shows the exact HMAC-SHA256 signature scheme this API requires.

2. **Azure Monitor Logs Ingestion API (recommended for new deployments)**: the modern Entra ID-based replacement for the Data Collector API. Requires a Data Collection Endpoint (DCE) and Data Collection Rule (DCR). Microsoft has the Data Collector API on a deprecation path; for production deployments, prefer the newer API or a managed Function / Logic App forwarder.

3. **Azure Function forwarder**: a small Function that consumes receipts from Service Bus / Storage queue and forwards them. Same downstream table.

## End-to-end smoke test

```bash
export PROVENEX_RECEIPT_PRIVATE_KEY_PATH=keys/private.pem
export PROVENEX_INDEX_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export AZURE_LAW_WORKSPACE_ID=<your-workspace-id>
export AZURE_LAW_SHARED_KEY=<primary-or-secondary-key>

python examples/sentinel_ingest.py
```

Produces one VERIFIED retrieval receipt and one denied tool-call receipt, signs with the HMAC scheme the Data Collector API requires, POSTs to `Provenex_Receipt_CL`, and prints the KQL query to verify they landed. Allow a few minutes for the rows to surface (normal Sentinel ingestion latency). With `AZURE_LAW_WORKSPACE_ID` unset, the script dumps the receipts to stdout for offline rehearsal.

## Deploy the analytics rules

```bash
az login
for rule in siem/sentinel/analytics_rules/*.json; do
  az sentinel alert-rule create \
      --resource-group <rg> \
      --workspace-name <workspace> \
      --rule-id $(uuidgen) \
      --rule "$(cat "$rule")"
done
```

Or via the Sentinel UI: Analytics -> Create -> Scheduled query rule -> paste the JSON.

The TAMPERED rule pages on Sentinel tactics `Impact` and `DefenseEvasion` (MITRE ATT&CK T1565 / T1562). The other two rules categorize by typical SOC tactics.

## Deploy the Workbook

```bash
az login
az monitor workbook create \
    --resource-group <rg> \
    --name "Provenex Overview" \
    --serialized-data "$(cat siem/sentinel/workbook.json)"
```

Or via Sentinel UI: Workbooks -> Add workbook -> Edit -> Advanced Editor -> paste `workbook.json`.

The Workbook ships seven panels mirroring the Splunk and Datadog dashboards:

| Panel | What it shows |
| --- | --- |
| Operating mode (24h) | Pie of `policy.mode` -- spot fleet still in `receipts_only`. |
| TAMPERED alarms (1h) | Critical rows; pair with the TAMPERED analytics rule for paging. |
| Denied tool calls by caller | Top 20 callers by deny count. |
| UNVERIFIED chunks by jurisdiction | Bar chart -- ingest gaps per jurisdiction. |
| Advisory-mode would-have-blocked | The advisory-rollout signal. |
| Drift detector alerts (7d) | Coalesced UNVERIFIED-fingerprint webhook events. |

## KQL field paths

The KQL queries assume the receipt JSON has been stored on the `Provenex_Receipt_CL` table with the schema 2.6.0 field paths under JSON-string columns (`policy_s`, `sources_s`, `summary_s`, etc. -- Sentinel auto-appends `_s` for string columns containing JSON). The Workbook and queries `parse_json` those columns and navigate the nested fields.

Examples of frequently-used field paths:

| KQL expression | Receipt JSON path |
| --- | --- |
| `tostring(parse_json(policy_s).mode)` | `policy.mode` (v1.0.0+) |
| `toint(parse_json(summary_s).tampered)` | `summary.tampered` |
| `tostring(parse_json(policy_s).access_control.policy_id)` | `policy.access_control.policy_id` |
| `caller_hash_s` | `caller_hash` (top-level string) |

## What this pack does NOT do

* Configure the ingestion pipeline (use Data Collector API, Logs Ingestion API, Function, or Logic App per your existing pattern).
* Set up Azure Sentinel itself; assumes a workspace is already provisioned.
* Validate against a running Sentinel by CI; the regression test in [`tests/test_siem_artifacts.py`](../../tests/test_siem_artifacts.py) covers JSON validity and field-path drift. Running against a real workspace requires operator credentials.
* Publish to Azure Marketplace; that's a separate operator step requiring a partner agreement and product review.

For the cross-vendor OCSF mapping that powers all three SIEM integrations, see [`docs/ocsf_mapping.md`](../../docs/ocsf_mapping.md).
