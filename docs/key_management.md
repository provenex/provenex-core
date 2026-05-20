# Key management

Provenex receipts are only as good as the integrity of the signing
key. This page covers what keys the system uses, what their threat
model is, and how to rotate them.

## What keys exist

| Key | Purpose | Lives in | Used by |
|---|---|---|---|
| **Index HMAC secret** | HMAC-SHA256 of every index row's `(fingerprint, doc, version, ingested_at, offset, length, entry_kind)` tuple. | Provenex pods (env var). | Ingester, verify pods. |
| **Receipt signing key** | Signature over each receipt's canonical payload. The integrity / non-repudiation anchor. | Provenex pods (env var or KMS handle). | Verify pods, admit pods. |
| **Ed25519 public key** | Verifier-only counterpart of the receipt key. Distributed openly. | Anywhere a receipt is verified. | Auditors, regulators, downstream services. |

The first two are "secret"; the third is "public" by design and is
expected to land on every laptop that ever verifies a Provenex receipt.

## Three signing backends

| Backend | Pros | Cons | When |
|---|---|---|---|
| `HmacSha256Signer` | Pure stdlib, fastest, simplest. | Symmetric; auditor needs the same secret. | Dev, internal-only, single-tenant. |
| `Ed25519Signer` | Asymmetric; public key alone verifies. ~1 µs sign latency. | Requires `[ed25519]` extra. | Production default. |
| KMS / HSM adapter (`AwsKmsSigner`, `GcpKmsSigner`, `AzureKeyVaultSigner`, `PKCS11Signer`) | Key never leaves KMS / HSM. Vendor handles rotation, audit, access policy. | KMS API latency (1-10 ms per sign), per-region failure mode. | Regulated production. |

Source: [provenex/kms/__init__.py](../provenex/kms/__init__.py) for
the full algorithm matrix per provider.

## Threat model

The receipt signing key has the same threat model as a CI signing key
or a code-signing certificate:

- **Confidentiality**: must not be exfiltratable from the pod.
- **Integrity**: must not be silently rotated by a malicious admin.
- **Availability**: a stale or revoked key means the verify path
  stalls; rotation must be operationally cheap.

The Provenex server reads the key (or KMS handle) from env at startup
and never writes it to disk. Combined with the read-only root
filesystem and `runAsNonRoot` security context in the Helm chart, the
key is bounded to the pod's runtime memory.

The Pattern C centralized service is the easier shape to harden: 3-5
verify pods is a smaller blast radius than every app pod holding a
key, which is why Pattern C is the default for regulated deployments.

## Rotation procedure

### HMAC

```bash
# 1. Compute the new secret out-of-band.
NEW=$(openssl rand -base64 32)

# 2. Update the Secret (in place — verify pods will pick it up on
#    next pod restart).
kubectl -n provenex create secret generic provenex-signing \
    --from-literal=index_secret="$NEW" --dry-run=client -o yaml \
    | kubectl apply -f -

# 3. Rolling restart so every pod re-reads the env var.
kubectl -n provenex rollout restart deploy/provenex-server
```

Note: rotating the **index** HMAC secret invalidates the per-row
signatures on already-ingested fingerprints (they were signed under
the old secret). For the index secret, rotation requires a re-ingest
or a dual-secret window. The receipt signing secret has no such
constraint — every new receipt is signed under the new secret, every
old receipt verifies under the old one.

### Ed25519

```bash
# 1. Mint a new keypair (HSM-backed in production).
openssl genpkey -algorithm ED25519 -out new.ed25519.pem

# 2. Update the Secret.
kubectl -n provenex create secret generic provenex-signing \
    --from-file=receipt_ed25519_pem=./new.ed25519.pem --dry-run=client -o yaml \
    | kubectl apply -f -

shred -u new.ed25519.pem

# 3. Publish the new public key so auditors can verify post-rotation
#    receipts. Common shape: commit the public key to the repo and
#    archive it in the receipt-retention bucket under
#    pubkeys/<yyyy>/<fingerprint>.pem.

# 4. Rolling restart.
kubectl -n provenex rollout restart deploy/provenex-server
```

Auditors keep every historical public key — receipts issued in 2024
verify under the 2024 public key, receipts issued in 2026 verify
under the 2026 public key. The receipt itself carries the
`signature.algorithm` field so the verifier knows which path to take.

### KMS / HSM

KMS-backed rotation is the smoothest path because the verifier
fetches the public key by KMS handle, not by PEM. The flow:

```bash
# 1. In AWS KMS: rotate the key (cmk rotation, automatic) or create
#    a new key version.
aws kms enable-key-rotation --key-id <key-id>

# 2. Provenex picks up the new public key on next ``DescribeKey``
#    call (cached at signer construction); a rolling restart picks
#    up the new key.
kubectl -n provenex rollout restart deploy/provenex-server
```

The KMS provider handles audit logging (CloudTrail / Cloud Audit
Logs / Azure Monitor) so the rotation is independently logged.

## HSM caveats

PKCS#11 support varies wildly across vendors. The `PKCS11Signer`
adapter is conservative: it only ships the RSASSA-PSS-SHA256 path
(universally supported). Ed25519 is documented as an extension point;
flip the mechanism in
[provenex/kms/pkcs11.py](../provenex/kms/pkcs11.py) once your token
supports `CKM_EDDSA`.

For AWS CloudHSM specifically: use the AWS KMS adapter rather than
PKCS#11 when you can. CloudHSM via KMS gives you the same key-isolation
property with less ceremony.

## Recovery

If a signing key is suspected compromised:

1. **Quarantine**: revoke the IAM permissions (`kms:Sign` on the AWS
   path) or pull the Secret (HMAC path). Verify pods will fail fast
   on the next sign attempt; the deployment goes into NotReady.
2. **Forensics**: pull the witness-log checkpoints from the audit
   bucket. Any receipt with an `issued_at` after the compromise
   window is suspect.
3. **Rotate**: follow the rotation procedure above. New receipts
   are issued under the new key.
4. **Notify**: regulators that consume your receipts need to be told
   which public key is current. Most enterprises ship the rotation
   notice via the existing security-advisory channel.

The receipt format is unchanged across rotations; only the public-key
distribution surface needs to be updated.
