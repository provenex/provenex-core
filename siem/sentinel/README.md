# Provenex Microsoft Sentinel pack

KQL queries + analytics-rule templates for ingesting Provenex
provenance receipts into Microsoft Sentinel.

## Files

- `kql/denied_tool_calls.kql` — last 24h of admission denials.
- `kql/unverified_by_jurisdiction.kql` — UNVERIFIED chunks grouped by
  request jurisdiction.
- `kql/drift_alerts.kql` — coalesced drift webhook events.
- `analytics_rules/unverified_spike.json` — analytics-rule template
  that fires when UNVERIFIED chunks exceed a threshold in a 1h window.
- `analytics_rules/tool_call_deny_burst.json` — fires when one caller
  hits >20 deny decisions inside 30 minutes.

## Install

Receipts arrive in a Sentinel-attached Log Analytics workspace via:

1. **HTTP Data Collector API** — POST receipts to the workspace's
   `https://<workspace-id>.ods.opinsights.azure.com/api/logs` with
   `Log-Type: Provenex_Receipt_CL`.
2. **Azure Function forwarder** — small function that consumes
   receipts from Service Bus / Storage queue and forwards them.

The `_CL` suffix is automatically appended for custom log types; the
queries below assume `Provenex_Receipt_CL` and `Provenex_Drift_CL`.

### Deploy analytics rules

```bash
az login
az sentinel alert-rule create \
    --resource-group <rg> \
    --workspace-name <workspace> \
    --rule-id $(uuidgen) \
    --rule "$(cat siem/sentinel/analytics_rules/unverified_spike.json)"
```

Or via the Sentinel UI: Analytics → Create → Scheduled query rule →
paste the KQL.

## What this pack does NOT do

- Configure the ingestion pipeline (use Data Collector API, Function,
  or Logic App per your existing pattern).
- Define workbooks; the KQL queries are workbook-friendly but
  workbook JSON is verbose and is left out to keep this pack small.
- Set up Azure Sentinel itself; assumes a workspace is already
  provisioned.
