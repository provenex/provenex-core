"""In-process SQLite bench shipped with the package.

The dev-tree ``bench/`` directory at the repo root contains the full
harness — synthetic + wiki corpora, multiple backends, Markdown
reports, the async Postgres bench — used to produce the numbers in
the README. This subpackage exposes a slimmer reproducer that ships
with the wheel and is accessible via ``provenex bench``. The point
is reproducibility on customer hardware against the same code path
the README publishes numbers from.

The shipped reproducer covers Pattern A only (in-process SQLite).
Pattern B (sidecar) and Pattern C (centralized async Postgres)
require a separate database and are out of scope for a one-command
reproducer; the dev-tree ``bench/`` covers those, and the README
links to the relevant scripts.
"""

from .scale import run, main, PRESETS

__all__ = ["run", "main", "PRESETS"]
