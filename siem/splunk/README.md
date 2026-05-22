# Provenex Splunk app

A small Splunk app that gives SOC analysts a starting dashboard over
Provenex receipts. Imports as a standard `.spl` bundle into Splunk
Enterprise / Splunk Cloud.

## What's inside

- `default/app.conf` — Splunk app metadata
- `default/props.conf` — JSON sourcetype `provenex:receipt`
- `default/transforms.conf` + `default/data/transforms/` — OCSF / CIM
  field extractions over the receipt JSON
- `default/savedsearches.conf` — three starter saved searches:
  - `provenex_denied_tool_calls_24h`
  - `provenex_unverified_chunks_by_jurisdiction`
  - `provenex_drift_alerts`
- `default/data/ui/views/provenex_overview.xml` — landing dashboard

## Install

```bash
# Local Splunk Enterprise:
cp -r siem/splunk $SPLUNK_HOME/etc/apps/provenex
$SPLUNK_HOME/bin/splunk restart

# Splunk Cloud / Cloud-managed:
zip -r provenex_splunk.spl siem/splunk
# Upload via Splunk Web → Apps → Manage Apps → Install app from file.
```

## Wire up the data input

The receipts flow into Splunk via your existing log forwarder. Two
common shapes:

1. **HEC (HTTP Event Collector)**: configure the receipt sink in
   Provenex to POST each receipt JSON to your HEC endpoint with
   sourcetype `provenex:receipt`.
2. **File tail**: write receipts to a JSONL file under
   `$SPLUNK_HOME/var/log/provenex/receipts.jsonl` and configure a
   `inputs.conf` file monitor with `sourcetype = provenex:receipt`.

Either shape is fine; the searches in this app are sourcetype-driven
so the upstream transport is interchangeable.

## Field extraction notes

The OCSF mapping is the canonical one from
[provenex.export.OCSFAdapter](../../provenex/export/ocsf.py). The
`provenex:receipt` sourcetype's `KV_MODE=json` automatic field
extraction surfaces every receipt field as a Splunk field; the CIM
overlay in `transforms.conf` adds the CIM-friendly aliases SOC tools
typically expect.

| Receipt path | CIM alias | OCSF class |
|---|---|---|
| `receipt_id` | `signature_id` | category=Audit Activity (1) |
| `request_binding.query_hash` | `request_id` | activity_id=4 (Lookup) |
| `caller_hash` | `user_id` | actor.user.uid_alt |
| `policy.access_control.policy_version_hash` | `signature` | metadata.product.version |
| `sources[*].verification_outcome` | `result` | status_detail |
| `sources[*].fingerprint` | `signature_hash` | resources.uid |

## Starter dashboard

`Apps → Provenex → Overview` shows three panels:

1. **Denied tool calls (last 24h)** - filters
   `policy.tool_call_control.decisions{}.decision="deny"` (the
   decisions array runs parallel to `actions[]` and is joined by
   `action_index`).
2. **UNVERIFIED chunks by jurisdiction** - count by
   `policy.access_control.decisions{}.inputs.request_context.jurisdiction`
   (request_binding holds only hashes; the verbatim request_context
   lives on the per-decision inputs subtree).
3. **Drift detector alerts** - pulls from the
   `provenex.index_drift` webhook events when Provenex's drift webhook
   posts to a Splunk HEC endpoint.
