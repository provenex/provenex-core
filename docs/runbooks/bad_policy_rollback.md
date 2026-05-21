# Runbook: bad policy push and rollback

This runbook covers the case where a policy change reaches
production and turns out to be wrong: too strict (legitimate
traffic gets blocked) or too loose (unauthorized traffic gets
through). It does not cover policy parse errors at deploy time;
those are caught before the policy ships.

## TL;DR

* Parse errors are caught at deploy time. The Policy CR is marked
  `Rejected` and the in-flight policy ConfigMap is untouched.
* Semantic errors (the policy parses but is wrong) flow through and
  affect verify / admission outcomes immediately. Rollback is the
  same shape as any GitOps change: re-apply the previous policy
  source.
* The receipt records the active policy's `policy_version_hash`
  on every decision. Use it to identify which receipts were issued
  under the bad policy.

## The two ways a policy reaches the server

There are two deployment paths, and the rollback differs.

### A. Policy CRD + operator (Kubernetes)

The operator validates `spec.policy` via `Policy.from_yaml(...)` on
every CR update. If validation fails it patches
`status.phase=Rejected` with the parse error and **does not** touch
the policy ConfigMap. The server keeps running on the last
accepted policy.

If the policy passes validation but is semantically wrong, the
operator updates the ConfigMap with annotation
`provenex.io/policy-version-hash=<hash>` and the server picks up
the new policy on its next reload (depends on your reload
mechanism — sidecar reloader, restart, or volume remount).

### B. Plain server (`PROVENEX_POLICY_FILE`)

The server reads `PROVENEX_POLICY_FILE` once at startup. Policy
parse errors prevent the server from starting; this is intentional
fail-closed behavior. Updating the policy means redeploying with a
new file content — typically a ConfigMap update + pod restart.

## Detection

Signals that the new policy is wrong, in order of how loud they
are:

1. **Verify endpoint 4xx/5xx rate spikes.** A policy that blocks
   too much shows up as `kept=0` on most requests or as 503s for
   admission denials. Watch `provenex_verify_blocked` and the
   `decision` label on `provenex_admit_total`.
2. **Customer reports.** "Suddenly nothing works for me" usually
   means a strict policy applied to a context that needs leniency
   (e.g., flipping `block_unverified=true` on a corpus that still
   has un-ingested chunks).
3. **Downstream audit anomalies.** A SIEM or anomaly detector
   correlating receipts by `policy.access_control.policy_version_hash`
   sees a new hash and starts counting denials grouped by caller.
4. **Compliance feedback.** A policy that is too loose surfaces
   when a regulator or internal audit reviews receipts and finds
   chunks that should have been denied.

## Identifying which receipts were issued under the bad policy

Every signed receipt with `policy.access_control` records the
canonical hash of the active policy in
`policy.access_control.policy_version_hash`. Same for tool-call
admissions under `policy.tool_call_control.policy_version_hash`.

To find the receipts to revisit:

```sql
-- example query against an OCSF-ish receipt log
SELECT receipt_id, issued_at, caller_hash
FROM receipts
WHERE policy_access_control_policy_version_hash = '<the bad hash>'
  AND issued_at BETWEEN '<rollout start>' AND '<rollback end>';
```

The hash is the same one the operator logged when it accepted the
CR (search the operator logs for `policy applied to ConfigMap ...
hash=<prefix>`). It is also recorded as a ConfigMap annotation
(`provenex.io/policy-version-hash`).

## Rollback procedure

The rollback shape depends on which deployment path is in use.

### A. Policy CRD + operator

1. **Confirm the current state.**
   ```bash
   kubectl get policy.provenex.io -n <ns> <name> -o yaml
   # Note status.policyVersionHash — that is the active hash.
   ```

2. **Re-apply the prior CR.** If your Policy CR is managed by
   GitOps (Flux, Argo, kustomize):
   * Revert the commit that introduced the change.
   * The operator reconciles the previous spec, validates it,
     and patches the ConfigMap back.

   If the CR is managed by hand:
   ```bash
   kubectl apply -f policy-cr-previous.yaml
   ```

3. **Wait for the server to reload.** Reload mechanism is your
   choice; common patterns:
   * Configmap-reload sidecar — the server picks up the new file
     on its next poll (usually within 60s).
   * Pod restart via rollout. This is the safest pattern for a
     bad policy: receipts after the rollback carry the prior
     `policy_version_hash` and customers see consistent behavior
     immediately.

4. **Confirm the rollback.** Verify the new
   `status.policyVersionHash` on the CR matches the previously
   accepted one, and that the server's next receipt carries that
   hash.

### B. Plain server

1. **Restore the previous ConfigMap (or file) content.** If the
   change went through GitOps, revert the commit. Otherwise apply
   the prior policy YAML to the same ConfigMap mounted at
   `PROVENEX_POLICY_FILE`.

2. **Restart the affected pods.** The server reads the policy
   once at startup; a rolling restart is required for the change
   to take effect:
   ```bash
   kubectl rollout restart deploy/provenex-server -n <ns>
   ```

3. **Confirm.** A receipt issued by a restarted pod will record
   the prior `policy_version_hash`.

## When the bad policy was *too loose*

A policy that lets through requests it should have blocked is the
worse failure mode, because the artifacts already shipped. The
rollback steps above stop the bleeding, but the receipts issued
during the window are still signed and still claim allow. Treat
those receipts as evidence to investigate:

* List the affected receipts (the SQL query above).
* Identify the decisions that would have been DENY under the
  correct policy. The policy evaluator's `decisions[]` records
  inputs at the time of the call, so you can re-run the corrected
  policy against the same inputs offline:

  ```python
  from provenex.policy.unified import Policy
  corrected = Policy.from_yaml("policy-corrected.yaml")
  # Re-evaluate the recorded inputs against the corrected policy.
  ```

* Open an incident with the receipts as the audit artifact. The
  signature is still valid; what changed is the policy in effect
  when they were issued.

## Prevention

1. **Stage policy changes against a canary deployment first.** The
   policy_version_hash on canary receipts tells you immediately
   whether the new policy is in effect.
2. **CI test policy changes against fixture inputs.** A policy
   diff that flips a decision on a fixture is a deliberate change;
   one that flips it accidentally is a bug.
3. **Use `policy_id`** in the YAML so the active policy identity
   is human-readable in receipts, not just a hash.
4. **Set `defaults.unknown_metadata: deny` and
   `defaults.policy_version_mismatch: deny`** in the
   access-control bundle. A policy that fails open on an
   unfamiliar input is the most common too-loose case.

## Related runbooks

* [index_unavailability.md](index_unavailability.md) — what happens
  when the verify backend can't be reached.
* [key_rotation.md](key_rotation.md) — signer rotation.
* [disaster_recovery.md](disaster_recovery.md) — total loss
  scenarios.
