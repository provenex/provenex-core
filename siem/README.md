# SIEM integrations

Connectors that bring Provenex receipts into the SOC's tool of choice. All three consume the receipt schema 2.6.0 wire format (v1.0.0+); the parsing rules know about the v1.0.0 `policy.mode` field so dashboards stay honest under each operating posture.

## Connectors

| Connector | Status | What it ships | Doc |
| --- | --- | --- | --- |
| **[Splunk](splunk/)** | TA-quality | `app.conf`, `props.conf`, `transforms.conf`, `tags.conf`, `eventtypes.conf`, 7 saved searches, 6-panel dashboard, packaging script for `.spl` | [`splunk/README.md`](splunk/README.md) |
| **[Datadog](datadog/)** | importable JSONs | Log pipeline, 8-widget dashboard, 3 monitors covering critical alarms | [`datadog/README.md`](datadog/README.md) |
| **[Microsoft Sentinel](sentinel/)** | KQL + analytics rules | 3 KQL queries, 2 analytics rule templates | [`sentinel/README.md`](sentinel/README.md) |

The shared spine is [`provenex.export.OCSFAdapter`](../provenex/export/ocsf.py) -- it maps any receipt onto OCSF v1.3, which all three SIEMs accept natively. The per-SIEM artifacts above are the transport + visualization wrappers; the OCSF mapping is the canonical translation. See [`docs/ocsf_mapping.md`](../docs/ocsf_mapping.md) for the field-by-field spec.

## End-to-end smoke tests

| Connector | Script |
| --- | --- |
| Splunk HEC | [`examples/splunk_hec_ingest.py`](../examples/splunk_hec_ingest.py) |
| Datadog Logs intake | [`examples/datadog_logs_ingest.py`](../examples/datadog_logs_ingest.py) |
| Sentinel HTTP Data Collector | (planned) |

Each script produces a small set of signed receipts (one allow, one deny) and POSTs them through the SIEM's ingestion API. Run with the SIEM credentials unset to dump the wire-format payloads to stdout for offline rehearsal.

## What does not ship in this repo

* Marketplace listings (Splunkbase, Datadog Marketplace, Azure Marketplace) -- those are operator steps that require partner agreements and product review.
* Live screenshots of the dashboards -- they render against your data; take one from your install for the marketplace listing.
* Live SIEM integration tests in CI -- the regression test in [`tests/test_siem_artifacts.py`](../tests/test_siem_artifacts.py) checks JSON validity and that no rule references a dead receipt-field path. Validating against a real SIEM is an operator pre-flight, not a CI gate.
