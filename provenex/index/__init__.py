"""Provenance index: abstract base + SQLite and Postgres implementations.

- :class:`provenex.index.sqlite_index.SQLiteProvenanceIndex` — single-node,
  stdlib-only. Good for development and single-pod deployments.
- :class:`provenex.index.postgres_index.PostgresProvenanceIndex` — multi-node
  production backend. Requires the ``postgres`` extra
  (``pip install "provenex-core[postgres]"``).

Both implement the same :class:`provenex.index.base.ProvenanceIndex` ABC
and share the same canonical HMAC payload, so receipts signed by one
backend verify against the other.
"""
