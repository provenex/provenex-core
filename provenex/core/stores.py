"""Store manifests: where registered copies live.

The provenance index stores fingerprints plus metadata, never content,
and deliberately knows nothing about the filesystem. That separation
breaks down for deletion attestation: an absence claim ("these values
are no longer in these stores") is only as strong as the enumeration
of stores it covers. Before this module, that enumeration lived in
each integrator's wrapper (a private ``manifest.json`` whose shape no
auditor could check).

A :class:`StoreManifest` makes the enumeration a product concept:

.. code-block:: json

    {
      "version": 1,
      "stores": [
        {
          "store_id": "agent-runtime-logs",
          "path_globs": ["/var/lib/agent/logs/**/*.jsonl"],
          "class": "runtime-log",
          "owner": "agent-runtime",
          "links": ["checkout-session-4821"]
        }
      ]
    }

``class`` is a free-form category meaningful to the operator (log,
cache, artifact, export, ...). ``links`` ties a store to entries or
requests it may hold copies for (document ids, session ids, request
ids); absence attestation uses it to report completeness per link.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

MANIFEST_VERSION = 1


@dataclass(frozen=True)
class Store:
    """One enrolled store: a set of files copies may live in."""

    store_id: str
    path_globs: Tuple[str, ...]
    store_class: str = "generic"
    owner: str = ""
    links: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "store_id": self.store_id,
            "path_globs": list(self.path_globs),
            "class": self.store_class,
            "owner": self.owner,
            "links": list(self.links),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Store":
        if not isinstance(d, dict):
            raise ValueError("store entry must be an object")
        store_id = d.get("store_id")
        if not isinstance(store_id, str) or not store_id:
            raise ValueError("store entry requires a non-empty 'store_id'")
        globs = d.get("path_globs")
        if not isinstance(globs, list) or not all(
            isinstance(g, str) for g in globs
        ):
            raise ValueError(
                f"store '{store_id}' requires 'path_globs': a list of glob strings"
            )
        return cls(
            store_id=store_id,
            path_globs=tuple(globs),
            store_class=str(d.get("class", "generic")),
            owner=str(d.get("owner", "")),
            links=tuple(str(x) for x in d.get("links", [])),
        )


@dataclass(frozen=True)
class StoreManifest:
    """The enrolled set of stores an absence claim covers."""

    stores: Tuple[Store, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": MANIFEST_VERSION,
            "stores": [s.to_dict() for s in self.stores],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StoreManifest":
        if not isinstance(d, dict):
            raise ValueError("store manifest must be an object")
        raw = d.get("stores")
        if not isinstance(raw, list):
            raise ValueError("store manifest requires a 'stores' list")
        stores = tuple(Store.from_dict(s) for s in raw)
        ids = [s.store_id for s in stores]
        if len(set(ids)) != len(ids):
            raise ValueError("store manifest has duplicate store_id values")
        return cls(stores=stores)

    @classmethod
    def load(cls, path: Path | str) -> "StoreManifest":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")

    def store_ids(self) -> List[str]:
        return [s.store_id for s in self.stores]


def expand_store(store: Store, base_dir: Optional[Path] = None) -> List[Path]:
    """Enumerate the files a store covers, sorted and de-duplicated.

    Relative globs resolve against ``base_dir`` (or the cwd). Directories
    matched by a glob are not files and are skipped. A glob that matches
    nothing is not an error here: absence attestation reports stores
    with zero files so the auditor sees the enumeration was empty, not
    silently skipped.
    """
    base = Path(base_dir) if base_dir is not None else Path.cwd()
    found: set[Path] = set()
    for pattern in store.path_globs:
        p = Path(pattern)
        if not p.is_absolute():
            # Split "prefix/**/*.ext" so glob() gets a rooted base.
            parts = p.parts
            split = next(
                (i for i, part in enumerate(parts) if any(c in part for c in "*?[")),
                len(parts),
            )
            root = base.joinpath(*parts[:split]) if split else base
            sub = "/".join(parts[split:]) or "*"
            candidates = root.glob(sub) if root.exists() else []
        else:
            parts = p.parts
            split = next(
                (i for i, part in enumerate(parts) if any(c in part for c in "*?[")),
                len(parts),
            )
            root = Path(*parts[:split]) if split else p.parent
            sub = "/".join(parts[split:]) or "*"
            candidates = root.glob(sub) if root.exists() else []
        for c in candidates:
            if c.is_file():
                found.add(c)
    return sorted(found)


def manifest_from_stores(stores: Sequence[Store]) -> StoreManifest:
    return StoreManifest(stores=tuple(stores))
