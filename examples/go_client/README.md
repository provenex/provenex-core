# Provenex Go client example

This is a stdlib-only Go program that proves the polyglot story:

> A non-Python service can hit the Provenex HTTP API, get back a
> signed provenance receipt, and verify the receipt offline using
> only the public artefact (HMAC secret here, Ed25519 public key in
> production).

No Provenex SDK is needed on the Go side. The receipt's canonical
JSON shape is the wire contract; any language with SHA-256, HMAC, and
JSON can verify.

## Run

```bash
# Start the Provenex server (see Dockerfile.server or examples/production_postgres/).
export PROVENEX_RECEIPT_SECRET="some-shared-hmac-secret"  # match the server's env
export PROVENEX_SERVER_URL="http://localhost:8080"        # default

go run main.go
```

Expected output:

```
server kept: [hello from the Go client]
offline signature verification: PASS
```

## What it does

1. Builds a SHA-256 fingerprint of one chunk, ingests it via
   `POST /v1/ingest`.
2. Calls `POST /v1/verify` for the same chunk; the server returns
   the kept/blocked split and a signed receipt.
3. Re-canonicalises the receipt (sorted keys, no whitespace,
   signature field removed), recomputes `HMAC-SHA256(canonical_bytes,
   secret)`, and compares to `receipt.signature.value`. The byte-level
   round-trip is the whole point: the receipt issuer and the Go
   verifier produce the same bytes from the same JSON without any
   shared library.

## Ed25519 path

For the production deployment shape, the server is started with
`PROVENEX_RECEIPT_PRIVATE_KEY_FILE` pointing at an Ed25519 PEM. The
Go verifier in that case skips the HMAC code and calls
`ed25519.Verify(pub, canonical_bytes, sig_bytes)` against the same
canonical payload. Only `receipt.signature.algorithm` changes (to
`"Ed25519"`); the payload computation is identical to the HMAC path
above. Swap the `verifyReceiptHMAC` function for a small Ed25519
verifier; everything else stays the same.

## Tests

The Python test `tests/test_server_http.py` exercises the same
round-trip (HMAC verification of the receipt after a verify call)
end-to-end. The Go program is the same story from the cross-runtime
direction.
