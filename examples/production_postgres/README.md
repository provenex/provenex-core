# Production deployment: Postgres provenance index

This example shows the recommended production-deployment shape for Provenex: a
shared Postgres index that multiple application pods write to and read from,
with each retrieval emitting a signed, offline-verifiable receipt.

## What's in this folder

| File | Purpose |
|---|---|
| `docker-compose.yml` | Brings up a local Postgres 16 on host port 5433 for the example to talk to. |
| `deployment.py` | The worked example: an ingester pod and a verify pod, sharing one Postgres index, ending with a signed receipt. |

## Prerequisites

```bash
pip install -e ".[postgres,policy]"   # if you haven't already
```

Docker (or any Postgres 13+ you can point at — see "Bring your own Postgres" below).

## Run it

```bash
# 1. Bring up Postgres
docker compose -f examples/production_postgres/docker-compose.yml up -d

# 2. Wait until it's healthy (a few seconds)
docker compose -f examples/production_postgres/docker-compose.yml ps

# 3. Run the example
export PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python examples/production_postgres/deployment.py
```

The script prints what each "pod" does, then ends with a signed receipt saved to
the current directory.

## Bring your own Postgres

If you already run Postgres (RDS, Aurora, Cloud SQL, Crunchy, Supabase, or your
own cluster), skip the docker-compose step and set the DSN yourself:

```bash
export PROVENEX_POSTGRES_DSN="postgresql://user:password@host:5432/dbname"
python examples/production_postgres/deployment.py
```

The script picks up `PROVENEX_POSTGRES_DSN` if set; otherwise it defaults to the
docker-compose DSN.

## Tear down

```bash
# Stop the container (keeps the data volume so a re-run is fast)
docker compose -f examples/production_postgres/docker-compose.yml down

# Or stop AND delete the data volume (fresh start next time)
docker compose -f examples/production_postgres/docker-compose.yml down -v
```

## What this example demonstrates (and what it does not)

**Demonstrates:**

- `PostgresProvenanceIndex` against a real Postgres
- Two separate `PostgresProvenanceIndex` instances (different connection pools)
  sharing one DB — the multi-pod shape
- Row-locked supersession across writers
- Tamper detection: a direct `UPDATE` bypassing the SDK is caught at verify
- Receipt portability: the canonical HMAC payload Postgres signs is bit-identical
  to what SQLite would sign — a receipt produced by one backend verifies under
  the other

**Does not demonstrate:**

- The Merkle transparency log over Postgres. See `MerklePostgresProvenanceIndex`
  and `examples/standalone_demo.py` for that — the Merkle layer composes on top
  of either index. For the OSS build, the recommended deployment is a single
  ingester pod when using the Merkle variant (see `docs/scaling.md`).
- Framework integration. See `examples/basic_langchain_rag.py` for LangChain;
  the Postgres index slots into any of the framework examples by swapping
  `SQLiteProvenanceIndex` for `PostgresProvenanceIndex` in the constructor.
