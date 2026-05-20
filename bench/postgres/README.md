# Postgres bench rig

A Docker Compose rig that stands up the Postgres backend used by
`bench/postgres_scale.py`, plus an optional PgBouncer in transaction
mode in front of it. Designed for anyone who wants to reproduce
[`docs/scaling.md`](../../docs/scaling.md)'s "Postgres at scale"
section or measure PgBouncer-fronted topologies that the laptop bench
doesn't stand up natively.

## What you get

| Service | Port | Notes |
|---|---|---|
| `postgres` (Postgres 16) | `localhost:5455` | Tuned for bench: 1 GB `shared_buffers`, 200 connections, 4 GB `max_wal_size`. |
| `pgbouncer` (1.20) | `localhost:5456` | Transaction-pool mode, 2000 client conns → 25 server conns. |

The Postgres data lives on a named volume (`pgdata`), so an ingest
survives `docker compose restart`. `docker compose down -v` wipes it.

## Quick start

```bash
cd bench/postgres
docker compose up -d

# Wait for healthy
docker compose ps
```

Then from the repo root, point the harness at the rig and run the full
bench:

```bash
export PROVENEX_TEST_POSTGRES_DSN='postgresql://postgres:bench@localhost:5455/postgres'
python -m bench.postgres_scale all --scale 1m \
    --pg-data-dir /var/lib/postgresql/data  # for cold-cache restart inside the container
```

(`--pg-data-dir` is the path *inside* the Postgres container. The
harness `subprocess.run(["pg_ctl", ...])` invocation needs to happen
*inside* the container to use that path; for the laptop run, see the
in-process ephemeral-pg pattern in `docs/scaling.md`. For the container
rig, prefer the `docker compose restart postgres` trick below.)

### Cold-cache the proper way (container restart)

Postgres shared_buffers + OS page cache are both flushed by restarting
the container:

```bash
docker compose restart postgres
sleep 5  # let it accept connections
python -m bench.postgres_scale verify-cold --scale 1m --verify-samples 200
```

This is the cleanest "true cold" measurement; `pg_ctl restart`
*inside* the container drops shared_buffers but not the host's page
cache. A full container restart drops both.

### Through PgBouncer

```bash
export PROVENEX_TEST_POSTGRES_DSN='postgresql://postgres:bench@localhost:5456/postgres'
python -m bench.postgres_scale connection-budget --scale 1m \
    --connection-budget-threads 1,10,100,1000 --duration 30
```

PgBouncer in transaction mode multiplexes thousands of client
connections onto ~25 server connections. The `connection-budget`
slice surfaces the curve: at what reader count does adding more
clients stop adding throughput?

## Stop & clean up

```bash
docker compose down       # stops, keeps the data volume
docker compose down -v    # stops AND deletes the data volume (full reset)
```

## Notes on the rig vs the laptop bench

`bench/postgres_scale.py` runs against any Postgres reachable via
`PROVENEX_TEST_POSTGRES_DSN`. The numbers in `docs/scaling.md` are
from a laptop with an ephemeral Postgres on a unix socket (no
container overhead, no PgBouncer). The rig in this directory is the
reproducibility envelope: pin the version, pin the tuning, run on
your own hardware, get comparable numbers.

The single biggest variable is the host disk. Local NVMe with WAL
fsync on lands in the 5-15k commit/s ingest range Postgres ops teams
expect; managed-Postgres GP3-EBS or Cloud SQL standard tiers will be
2-5× slower on per-row ingest. Batched ingest (multiple chunks per
transaction) is the right tuning lever; see the OSS commercial
roadmap for the planned `add_many` API.
