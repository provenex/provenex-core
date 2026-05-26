# Provenex on Datadog

A log integration for Provenex receipts in Datadog: a parsing pipeline that maps receipt fields onto Datadog's reserved attributes, a starter dashboard, and three monitors covering the critical alarms. Compatible with provenex-core 1.0.0 (receipt schema 2.6.0+).

## What's inside

```
siem/datadog/
├── pipeline.json                 # Datadog Logs pipeline (filter source:provenex)
├── dashboard.json                # Importable dashboard (8 widgets across 4 rows)
└── monitors/
    ├── tampered_receipts.json    # Critical: any TAMPERED outcome in 15m
    ├── tool_call_deny_burst.json # High: 20+ denies per caller in 30m
    └── unverified_spike.json     # Warning: 50+ UNVERIFIED in 1h
```

## Send receipts to Datadog

Receipts flow into Datadog via the Logs HTTP intake. The Provenex sink ships them as JSON; the pipeline parses and tags. There are two transport shapes:

1. **Datadog Logs intake (direct POST).** Configure the Provenex receipt sink (or a `FileJSONLSink` followed by a forwarder) to POST each receipt JSON to `https://http-intake.logs.<DD_SITE>/api/v2/logs` with `ddsource=provenex`. The end-to-end smoke test in [`examples/datadog_logs_ingest.py`](../../examples/datadog_logs_ingest.py) shows the exact envelope.
2. **Datadog Agent log tail.** Write receipts to a JSONL file (e.g. `/var/log/provenex/receipts.jsonl`) and configure the Datadog Agent to tail it with `source: provenex` and `service: provenex.receipt`. Same downstream pipeline, different transport.

The pipeline matches `source:provenex` and applies the processors regardless of which transport delivered the receipt.

## Install the pipeline + dashboard + monitors

Import each JSON via the Datadog API or the UI. The API import is the right path for IaC / Terraform; the UI import is the right path for a manual first install.

### API (curl)

```bash
DD_API_KEY=...                       # operator's API key
DD_APP_KEY=...                       # operator's App key
DD_SITE=datadoghq.com                # or .eu, us3, us5, ap1...

# Pipeline
curl -X POST "https://api.${DD_SITE}/api/v1/logs/config/pipelines" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
  -H "Content-Type: application/json" \
  -d @siem/datadog/pipeline.json

# Dashboard
curl -X POST "https://api.${DD_SITE}/api/v1/dashboard" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
  -H "Content-Type: application/json" \
  -d @siem/datadog/dashboard.json

# Monitors (one per file)
for m in siem/datadog/monitors/*.json; do
  curl -X POST "https://api.${DD_SITE}/api/v1/monitor" \
    -H "DD-API-KEY: ${DD_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
    -H "Content-Type: application/json" \
    -d @"$m"
done
```

### UI

* **Pipeline**: Logs -> Configuration -> Pipelines -> New Pipeline -> Import. Paste `pipeline.json`.
* **Dashboard**: Dashboards -> New Dashboard -> three-dot menu -> Import dashboard JSON. Paste `dashboard.json`.
* **Monitors**: Monitors -> New Monitor -> Import. Paste each file under `monitors/`.

## End-to-end smoke test

```bash
export PROVENEX_RECEIPT_PRIVATE_KEY_PATH=keys/private.pem
export PROVENEX_INDEX_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export DD_API_KEY=<your-api-key>
export DD_SITE=datadoghq.com

python examples/datadog_logs_ingest.py
```

The script produces a VERIFIED retrieval receipt and a denied tool-call receipt, wraps each in the Datadog intake envelope (`ddsource=provenex`, `service=provenex.receipt`), POSTs to the intake, and prints the Logs Explorer query to verify they landed. With `DD_API_KEY` unset, the script dumps the envelope JSON to stdout for offline rehearsal.

## What the pipeline does

The Datadog pipeline (filter: `source:provenex`) applies these processors in order:

| Processor | Effect |
| --- | --- |
| **Service remapper** | Sets the Datadog `service` from `sourcetype` (`provenex.receipt` or `provenex.drift`). |
| **Date remapper** | Sets the event timestamp from `issued_at` -- events land at the receipt time, not the ingest time. |
| **Category processor** | Derives a status category from `summary.tampered`, `summary.unauthorized`, `summary.unverified`, `summary.overall_status`, and `policy.mode`. Encodes the v1.0.0 fact that `receipts_only` / `advisory` events never block, so a `FAIL` overall status is "notice" (would-have-blocked) rather than "error" (did-block). |
| **Status remapper** | Promotes the derived category to Datadog's reserved `status` (critical / error / warning / notice / info). |
| **Attribute remappers** | `caller_hash -> usr.id`, `receipt_id -> event_id`, `trajectory.trajectory_id -> session_id`. The user attribute lets every Datadog dashboard that pivots on `@usr.id` see Provenex events. |
| **Message remapper** | Sets the displayed message to `summary.overall_status` so the log list view is scannable. |

## Status mapping

| Receipt shape | Datadog status |
| --- | --- |
| `summary.tampered > 0` | **critical** (the alarm condition; pages SHOULD fire) |
| `summary.unauthorized > 0 AND policy.mode == enforce` | error |
| `summary.unverified > 0 OR summary.overall_status == FAIL` | warning |
| `policy.mode in (receipts_only, advisory)` | notice (informational; receipt-only postures) |
| anything else | info |

## Starter dashboard

The starter dashboard ships eight widgets across four rows:

| Row | Widget | What it shows |
| --- | --- | --- |
| 1 | Operating mode (24h) | Top-list of `policy.mode` -- spot fleet still in `receipts_only` when production should be `enforce`. |
| 1 | TAMPERED alarms (1h) | Big-number with conditional red formatting on > 0. |
| 2 | Denied tool calls (24h) | Top-list of `usr.id` for `tool_call_control.decisions.decision:deny`. |
| 2 | UNVERIFIED chunks by jurisdiction (24h) | Timeseries grouped by `request_context.jurisdiction`. |
| 3 | Advisory-mode "would have blocked" (24h) | Top-list of `policy_id` -- the rollout signal. |
| 3 | Drift detector alerts (7d) | Top-list of hosts with `provenex.drift` events. |
| 4 | Receipt volume by outcome (24h) | Timeseries grouped by `summary.overall_status`. |

A screenshot is not bundled in the repo (Datadog dashboards render against live data); take one from your install for the marketplace listing and your internal runbook.

## Monitors shipped

| Monitor | Triggers on | Severity |
| --- | --- | --- |
| `tampered_receipts.json` | Any TAMPERED receipt in 15m | Critical (P1). Pages secops; the runbook is in the monitor message. |
| `tool_call_deny_burst.json` | More than 20 denies from one caller in 30m | High (P2). Distinguishes misconfig from probe. |
| `unverified_spike.json` | More than 50 UNVERIFIED in 1h | Warning (P3). Usually ingest-pipeline gaps, sometimes poisoning. |

Tune thresholds for your baseline traffic; the defaults assume a small/dev deployment.

## What ships, what does not

* **Ships in this repo**: the pipeline JSON, the dashboard JSON, the three monitor JSONs, the end-to-end smoke test.
* **Not in this repo**: a Datadog Marketplace listing (separate operator step; Datadog Marketplace integrations require an integration tile package, partner agreement, and review). The artifacts here are usable today via direct API import; the marketplace tile is the polished distribution channel.
* **Not validated against a live Datadog tenant by CI**: the regression test in [`tests/test_siem_artifacts.py`](../../tests/test_siem_artifacts.py) covers the JSON validity and field-path drift checks; running against a real Datadog requires operator credentials.

For the cross-vendor OCSF mapping that powers all three SIEM integrations, see [`docs/ocsf_mapping.md`](../../docs/ocsf_mapping.md).
