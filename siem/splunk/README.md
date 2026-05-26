# Provenex Splunk app

A Splunk Technology Add-on (TA) that parses Provenex receipts, maps fields to Splunk's Common Information Model, and ships a starter dashboard for AI-provenance findings. Installs as a standard `.spl` bundle into Splunk Enterprise or Splunk Cloud.

Compatible with provenex-core 1.0.0 (receipt schema 2.6.0); older receipts (2.5.0 and earlier) are also handled correctly, the `policy.mode` field is just absent.

## What's inside

```
siem/splunk/
├── default/
│   ├── app.conf              # app metadata + version
│   ├── props.conf            # sourcetypes provenex:receipt + provenex:drift,
│   │                         # CIM field aliases, EVAL-derived action/severity
│   ├── transforms.conf       # regex-based REPORT extractors
│   ├── tags.conf             # CIM datamodel tagging
│   ├── eventtypes.conf       # named groupings the tags attach to
│   ├── savedsearches.conf    # 7 starter searches (see below)
│   └── data/ui/views/
│       └── provenex_overview.xml   # 6-panel landing dashboard
└── README.md                 # this file
```

## Install

Run `scripts/package_splunk_app.sh` from the repo root to produce a deployable bundle:

```bash
./scripts/package_splunk_app.sh
# wrote dist/provenex-splunk-1.0.0.spl
```

Then install:

```bash
# Splunk Enterprise / self-managed:
cp dist/provenex-splunk-1.0.0.spl $SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/bin/splunk restart

# Splunk Cloud / Cloud-managed:
# Apps -> Manage Apps -> Install app from file -> dist/provenex-splunk-1.0.0.spl
```

Splunkbase publication is a separate operator step; the bundle produced above is the artifact you upload there.

## Wire up the data input

Receipts flow into Splunk via your existing log transport. Two common shapes:

1. **HEC (HTTP Event Collector)**: configure the Provenex receipt sink to POST each receipt JSON to your HEC endpoint with `sourcetype="provenex:receipt"`. The end-to-end smoke test in [`examples/splunk_hec_ingest.py`](../../examples/splunk_hec_ingest.py) shows the exact shape; pipe the producer side through a `RetryQueueSink` for durability across broker hiccups.
2. **File tail**: write receipts to JSONL via `FileJSONLSink` (e.g. `$SPLUNK_HOME/var/log/provenex/receipts.jsonl`) and configure a `inputs.conf` file monitor with `sourcetype = provenex:receipt`.

Drift detector events ship with `sourcetype="provenex:drift"`; same transport choices.

## End-to-end smoke test

```bash
export PROVENEX_RECEIPT_PRIVATE_KEY_PATH=keys/private.pem
export PROVENEX_INDEX_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export SPLUNK_HEC_URL=https://splunk.example.com:8088
export SPLUNK_HEC_TOKEN=<your-hec-token>

python examples/splunk_hec_ingest.py
```

The script produces a VERIFIED retrieval receipt and a denied tool-call receipt, POSTs both to HEC, and prints the Splunk search expression to verify they landed. With `SPLUNK_HEC_URL` unset, the script dumps the same receipts to stdout — useful for offline rehearsal and for piping into your own HEC client.

## Field extraction

The receipt JSON is auto-extracted by Splunk's `KV_MODE=json` parser. The CIM overlay translates the receipt-native field names to the Splunk CIM datamodels:

| Receipt path | CIM field | CIM datamodel |
| --- | --- | --- |
| `receipt_id` | `signature_id` | Audit Activity |
| `caller_hash` | `user`, `user_id` | Authentication, Audit |
| `issuer` (`provenex-core/X.Y.Z`) | `vendor`, `product`, `product_version` | Vendor Product |
| `policy.access_control.policy_id` | `app` | Web |
| `summary.overall_status` + `policy.mode` | `action` (`logged` / `advisory` / `allowed` / `blocked`) | Authentication |
| `summary.tampered/unauthorized/unverified` | `severity`, `severity_id` | Alerts |
| `sources[].fingerprint` | `signature_hash` | Audit |
| `sources[].verification_outcome` | `result` | Audit |

The `action` mapping is the one v1.0.0 added: in `receipts_only` mode the engine never blocks, so `overall_status=FAIL` (a "would-have-blocked" event) reads as `action=logged` rather than `action=blocked`. SOC dashboards that pivot on `action` therefore stay honest under each operating posture.

## Starter dashboard

`Apps -> Provenex -> Overview` ships with six panels:

| Row | Panel | What it shows |
| --- | --- | --- |
| 1 | Operating mode (24h) | Pie chart of `policy.mode` -- spot fleet still in `receipts_only` when production should be `enforce`. |
| 1 | TAMPERED alarms (1h) | Table of receipts whose row HMAC failed. Critical: signing key may be compromised. |
| 2 | Denied tool calls (24h) | Caller leaderboard for tool-call admission denies. |
| 2 | Top callers by deny rate (24h) | Per-caller deny rate (≥10 receipts). The "who is the policy stopping the most?" view. |
| 3 | UNVERIFIED chunks by jurisdiction (24h) | Spot ingest gaps per jurisdiction. |
| 3 | Advisory-mode "would have blocked" (24h) | Use during a controlled rollout: when this stops firing, the policy is ready to flip to `enforce`. |
| 4 | Drift detector alerts (7d) | Coalesced UNVERIFIED-fingerprint webhook events. |

A screenshot is not bundled in the repo (Splunk dashboards render against live data); take one from your install and add it to your internal runbook.

## Saved searches

The dashboard panels call the saved searches in `savedsearches.conf`:

| Saved search | Purpose |
| --- | --- |
| `provenex_denied_tool_calls_24h` | Caller-level deny counts in the last 24h. |
| `provenex_unverified_chunks_by_jurisdiction` | UNVERIFIED counts grouped by `request_context.jurisdiction`. |
| `provenex_drift_alerts` | Drift webhook events in the last 7d. |
| `provenex_tampered_alarms` | TAMPERED outcomes in the last 1h. Severity 5 (Critical), suppression 15m, ready for `alert_actions` wiring. |
| `provenex_receipts_by_mode_24h` | Fleet posture audit by `policy.mode`. v1.0.0+. |
| `provenex_top_callers_by_denial_rate_24h` | Top 20 callers by deny rate (min 10 receipts). |
| `provenex_advisory_would_have_blocked_24h` | The advisory-rollout signal: fires when a policy in `advisory` mode would have blocked. |

Pair `provenex_tampered_alarms` with a Splunk alert action (PagerDuty, OpsGenie, Slack, email) for the always-on TAMPERED page.

## What ships, what does not

* **Ships in this repo**: the configs above, the dashboard XML, the saved searches, the HEC-ingest smoke test.
* **Not in this repo**: a Splunkbase listing (separate operator step), the dashboard screenshot (take one from your install), the OCSF tagging (handled by `provenex-core`'s `OCSFAdapter` upstream of Splunk -- see [`docs/ocsf_mapping.md`](../../docs/ocsf_mapping.md)).
* **Not validated against a running Splunk by CI**: the regression test in [`tests/test_siem_artifacts.py`](../../tests/test_siem_artifacts.py) checks the configs reference only live receipt-field paths; running the artifacts against a real Splunk install is the operator's responsibility.
