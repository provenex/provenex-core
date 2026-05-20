# Runbook: signing-key rotation

How to rotate the receipt-signing key (HMAC or Ed25519) without breaking outstanding receipts. This runbook is for the operator running Provenex in production. It covers the signing key only; the provenance-index HMAC secret is a separate key with a separate procedure (covered in the [Postgres operations runbook](postgres_operations.md) and [disaster recovery runbook](disaster_recovery.md)).

The procedure is operational. The cryptographic guarantees that make it safe come from the design of the receipt format ([receipt_format.md](../receipt_format.md)) and the signer interface ([provenex/core/receipt.py](../../provenex/core/receipt.py)). This runbook turns those guarantees into a step list.

## Why rotation is safe

A Provenex receipt is verified against the key material the verifier holds, not against any Provenex-internal state. The OSS layer keeps no key-to-receipt registry; the `signature.algorithm` field on each receipt declares which primitive was used, and the verifier picks the matching key from its own keystore. Rotating a signing key therefore does not invalidate prior receipts: the prior key continues to verify them as long as the verifier still has access to it.

This means rotation is additive on the verifier side: new emissions use the new key; the old key joins the verification chain. The operator's job is to keep both keys in the verifier's keystore for as long as receipts under the old key are still in scope (per your retention policy), and to switch the signing host over cleanly.

## Required inputs

| Input | When required |
| --- | --- |
| The current signing key | Always (the host that mints receipts holds it). |
| The new signing key | Generated during the procedure. |
| Access to the secrets manager that stores the keys | Required to deploy the new key and (optionally) retire the old one. |
| The list of receivers / auditors who hold the verifier-side key material | For Ed25519: distribute the new public key out-of-band before cutover. For HMAC: only relevant if the verifier is a different team or org (which is unusual; HMAC is for in-house use). |
| The dual-key window duration | Operator-chosen. Recommended: at least one full retention cycle for receipts signed under the old key. |

## The dual-key window

During rotation, two signer instances run in parallel:

- The **old signer** continues to verify receipts that were emitted under the old key.
- The **new signer** mints new receipts and also continues to verify any new receipts under the new key.

A single verifier process holds both keys in its keystore and dispatches on `signature.algorithm` (for Ed25519, also on the key identifier the verifier records out-of-band; for HMAC, on the deployment context). The verifier never needs to know which receipt was signed when; it tries each key in turn and accepts the first that validates.

The dual-key window has two distinct durations:

- **On the signing host:** the old key remains until the cutover is complete (typically minutes to hours).
- **On verifying hosts:** the old key remains for as long as receipts signed under it are still in scope for audit. For deployments with multi-year retention, that means the old key stays in the verifier's keystore for the full retention period, even after the signing host has retired it.

## HMAC rotation procedure

HMAC keys are symmetric: the same secret signs and verifies. Rotation is simpler than Ed25519 because there is no public-key distribution, but the secret must reach every verifier.

1. **Generate the new secret.** 32 bytes of cryptographically secure random data:

    ```bash
    python3 -c 'import secrets; print(secrets.token_hex(32))'
    ```

2. **Store the new secret in the secrets manager** under a new identifier alongside the existing secret (do not overwrite). Convention: prefix with a date or a monotonically-increasing version, e.g. `provenex/receipt_secret/2026_05_20`.

3. **Distribute the new secret to every verifying host** that needs to verify newly-signed receipts. Verifier code reads the secret from the same secrets manager the signer reads from; the new secret arrives via the next read.

4. **Deploy the new signer.** Update the signing host to read `PROVENEX_RECEIPT_SECRET` (or pass `secret=` to `HmacSha256Signer` explicitly) pointing at the new secret. Rolling deploy is supported because each receipt is signed independently; mid-deploy a fraction of receipts will be signed under the new key while the rest finish under the old. Both verify cleanly.

5. **Confirm new receipts validate under the new secret.** Audit a sample of post-cutover receipts via `provenex audit` with the new secret in `PROVENEX_RECEIPT_SECRET`. Expected: PASS on the new receipts; FAIL on old receipts unless the verifier also holds the old secret.

6. **Retain the old secret** on every verifier for as long as receipts signed under it are in scope for audit. The signing host can retire the old secret immediately after step 5.

7. **Document the cutover.** Record the time of cutover, the new secret identifier, and the retention deadline for the old secret. The receipt's `issued_at` field plus the cutover time tells a future auditor which key signed any given receipt.

The HMAC variant of the secret can also be the index-row secret, but use distinct secrets per role (`PROVENEX_RECEIPT_SECRET` vs `PROVENEX_INDEX_SECRET`); sharing one secret means anyone who can write a row in the index can also forge a receipt signature. The legacy shared `PROVENEX_SIGNING_SECRET` is supported with a `DeprecationWarning`. See [secure_defaults.md § Signing-key storage](../secure_defaults.md#signing-key-storage).

## Ed25519 rotation procedure

Ed25519 keypairs are asymmetric: the private key signs, the public key verifies. The public key must reach every external auditor before cutover so they can validate post-cutover receipts.

1. **Generate the new keypair.**

    ```python
    from provenex import Ed25519Signer
    signer = Ed25519Signer.generate()
    private_pem = signer.private_key_pem(password=b"<a strong password>")
    public_pem = signer.public_key_pem()
    ```

    Save the encrypted `private_pem` in your secrets manager. Save `public_pem` in a location auditors can reach (a published distribution list, an HTTPS endpoint, an out-of-band channel).

2. **Distribute the new public key** to every external auditor or compliance recipient who holds the prior public key. Include the cutover date. Auditors keep both public keys in their verification chain.

3. **Deploy the new signing host configuration** with the new private key. The `Ed25519Signer.from_private_key_pem(pem_bytes, password=b"...")` factory loads the key; pass the resulting signer to every emission entrypoint that previously used the old signer.

4. **Confirm new receipts validate under the new public key.**

    ```bash
    provenex audit receipt.json --public-key new_public.pem
    ```

    Expected: PASS on post-cutover receipts; FAIL on pre-cutover receipts under the new public key, PASS under the old public key. The auditor verifies any receipt by trying each public key they hold.

5. **Retire the old private key on the signing host.** The signing host no longer needs it; the verifying side keeps the old public key.

6. **Keep both public keys in the verifier chain** for as long as receipts signed under either key are in scope for audit. Public keys are not sensitive; storing them indefinitely has no security cost.

7. **Document the cutover.** Record the time, the new public key's fingerprint, and the schedule for any subsequent rotations. Auditors will reference these when verifying historical receipts.

The same procedure works whether the private key lives in process memory (the default `Ed25519Signer`) or in a future KMS-backed signer (see below). The signer interface stays the same; the loader changes.

## KMS-backed rotation (forward-looking)

A KMS-backed Ed25519 signer is on the commercial roadmap; see [provenex.ai](https://provenex.ai). Once it ships, the rotation procedure simplifies on the signing host because the KMS handles key generation, storage, and rotation natively. The auditor-side procedure does not change: the verifier still holds a public key (or a list of public keys across rotations) and validates receipts against them.

Until the KMS-backed signer ships, the Ed25519 procedure above is the right pattern. Store the encrypted private PEM in your secrets manager and read it at signer-startup; do not check the key into source control.

## Failure modes mid-rotation

**Symptom: new receipts produce `signature.algorithm` mismatches at the verifier.** Cause: the verifier is using the old signer class for the wrong algorithm (e.g. trying HMAC where the receipt is Ed25519, or vice versa). Fix: the verifier dispatches on the receipt's own `signature.algorithm` field. If the verifier code does not, update it; the `provenex audit` CLI handles this correctly by default.

**Symptom: a verifier rejects every receipt with INVALID after a cutover.** Cause: the verifier received the new key in the wrong format (PEM line endings, wrong password, wrong identifier) or did not pick up the new key from the secrets manager. Fix: re-read the key from the secrets manager and re-test against a known-good post-cutover receipt. Roll back to the old key on the signing host if the verifier cannot be fixed within the audit-deadline window.

**Symptom: the old private key is destroyed before the dual-key window closes.** Cause: a misread of the rotation procedure as "replace key" rather than "add new key". Consequence: receipts signed under the old key still verify (the private key is not needed for verification), but if you ever need to re-sign a pre-cutover receipt under a new audit context, the option is gone. Re-signing is rare; the more common consequence is that the audit trail loses the option of being re-signed during a key-compromise response.

**Symptom: a single receipt was signed during the cutover and verifies against neither key.** This should not happen: each receipt is signed independently and atomically; a half-signed receipt is a code bug, not an operational artifact. If it does happen, treat the receipt as invalid (the signature does not verify against any key the verifier holds) and investigate the signing host.

**Symptom: the cutover is rolled back mid-procedure.** Both old and new keys remain in the secrets manager and on the verifier; new receipts mint under the old key again. The rollback has no audit impact; just record the rollback in the operations log so a future auditor sees the timeline.

## Read next

- [secure_defaults.md § HMAC vs Ed25519](../secure_defaults.md#hmac-vs-ed25519): the trade-off table for choosing the signer.
- [secure_defaults.md § Signing-key storage](../secure_defaults.md#signing-key-storage): where keys live.
- [threat_model.md § What if our signing key is compromised tomorrow?](../threat_model.md#what-if-our-signing-key-is-compromised-tomorrow): the threat-model framing of compromise vs rotation.
- [witness_log.md](witness_log.md): the witness log discipline that complements key rotation against a key-holding adversary.
- [disaster_recovery.md](disaster_recovery.md): the broader incident-response runbook, including key compromise.
