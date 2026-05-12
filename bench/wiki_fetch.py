"""Fetch a deterministic snapshot of Wikipedia articles for the benchmark.

Usage::

    python -m bench.wiki_fetch --count 15000 --cache-dir bench/wiki_cache

Why a snapshot? The bench numbers must be reproducible. Live network
calls during a measured run would inject latency we don't control and
make every run a different size. Fetch once, write to disk, reuse on
every bench invocation.

Output layout::

    <cache-dir>/
        manifest.txt           # one article title per line, in fetch order
        articles/
            <hash>.txt         # plain text of the article body

The fetcher is idempotent: re-running with the same --count and --seed
skips already-cached articles. Increase --count to extend the snapshot
without re-downloading what you already have.

Network etiquette:
    * Custom User-Agent (required by the Wikipedia API terms).
    * 1 request at a time, with a configurable inter-request delay.
    * Plain text via ``prop=extracts&explaintext=1`` (no HTML parsing).
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import random
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterator, List, Optional

# Transient errors worth retrying. Wikipedia's edge occasionally closes
# keep-alive connections mid-flight (RemoteDisconnected) and very rarely
# drops bytes (IncompleteRead). socket.timeout is also seen during peaks.
_TRANSIENT_EXC = (
    http.client.RemoteDisconnected,
    http.client.IncompleteRead,
    ConnectionResetError,
    socket.timeout,
    TimeoutError,
    urllib.error.URLError,
)

_API = "https://en.wikipedia.org/w/api.php"
_USER_AGENT = (
    "ProvenexBench/0.1 (https://github.com/provenex; bench@provenex.local) "
    "Python-urllib"
)


def _ssl_context() -> ssl.SSLContext:
    """Return an SSL context with a working CA bundle.

    The Python.org macOS installer ships without a working cert.pem until the
    user runs ``Install Certificates.command``, which we can't assume. Fall
    back to the macOS system bundle at ``/etc/ssl/cert.pem``, then to
    ``SSL_CERT_FILE`` if set. On Linux the platform defaults already work.
    """
    cafile = os.environ.get("SSL_CERT_FILE")
    if not cafile:
        for candidate in ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"):
            if os.path.exists(candidate):
                cafile = candidate
                break
    return ssl.create_default_context(cafile=cafile)


_SSL_CTX = _ssl_context()


def _api_get(params: dict) -> dict:
    """One GET against the MediaWiki API, JSON-decoded."""
    query = urllib.parse.urlencode({**params, "format": "json"})
    url = f"{_API}?{query}"
    last_exc: Optional[BaseException] = None
    for attempt in range(5):
        req = urllib.request.Request(
            url,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except _TRANSIENT_EXC as exc:
            last_exc = exc
            # Exponential backoff: 0.5s, 1s, 2s, 4s, 8s.
            time.sleep(0.5 * (2 ** attempt))
    raise RuntimeError(f"giving up on {url!r} after 5 attempts: {last_exc!r}")


def _iter_titles(seed: int, batch: int = 200) -> Iterator[str]:
    """Yield article titles deterministically, walking the alphabetical index.

    The walk starts at a seed-derived ``apfrom`` prefix and pages forward.
    Same seed -> same starting point -> same title sequence.
    Redirects, disambiguation pages, and obvious stubs are skipped.
    """
    rng = random.Random(seed)
    # Two-letter prefix gives enough entropy without landing on empty slots.
    prefix = "".join(rng.choices(string.ascii_lowercase, k=2)).capitalize()
    apfrom: Optional[str] = prefix

    while apfrom is not None:
        data = _api_get(
            {
                "action": "query",
                "list": "allpages",
                "apnamespace": "0",
                "apfilterredir": "nonredirects",
                # Filter on wikitext bytes. 20KB wikitext ~= 10KB plaintext after
                # markup stripping; gives us ~12-15 chunks per article at the
                # default 800-char window. Tradeoff: fewer articles needed for
                # a given chunk target, slightly less variety.
                "apminsize": "20000",
                "aplimit": str(batch),
                "apfrom": apfrom,
            }
        )
        pages = data.get("query", {}).get("allpages", [])
        for page in pages:
            title = page.get("title")
            if title:
                yield title
        cont = data.get("continue", {})
        apfrom = cont.get("apcontinue")


def _extract_plaintext(title: str) -> Optional[str]:
    """Return the plain-text body of ``title`` or None if not retrievable."""
    data = _api_get(
        {
            "action": "query",
            "prop": "extracts",
            "explaintext": "1",
            "redirects": "1",
            "titles": title,
        }
    )
    pages = data.get("query", {}).get("pages", {})
    for _pid, page in pages.items():
        text = page.get("extract")
        # Floor on the extracted plaintext: with our 800-char chunk window,
        # we want articles that produce at least ~6 chunks of useful data.
        if text and len(text) >= 5_000:
            return text
    return None


def _slug(title: str) -> str:
    """Filename-safe stable key for a title."""
    return hashlib.sha256(title.encode("utf-8")).hexdigest()[:24]


def fetch_snapshot(
    cache_dir: Path,
    count: int,
    seed: int,
    sleep_seconds: float,
) -> List[str]:
    """Populate ``cache_dir`` with up to ``count`` articles. Idempotent.

    Returns the manifest (list of titles in fetch order). On re-run, the
    manifest is extended only if ``count`` exceeds the existing length.
    """
    articles_dir = cache_dir / "articles"
    manifest_path = cache_dir / "manifest.txt"
    articles_dir.mkdir(parents=True, exist_ok=True)

    existing: List[str] = []
    if manifest_path.exists():
        existing = [
            line.strip()
            for line in manifest_path.read_text().splitlines()
            if line.strip()
        ]

    if len(existing) >= count:
        return existing[:count]

    print(
        f"[wiki-fetch] cache has {len(existing)} articles; need {count}",
        file=sys.stderr,
    )

    manifest = list(existing)
    seen = set(manifest)
    title_iter = _iter_titles(seed=seed)
    # Fast-forward past already-cached titles. The iterator is deterministic
    # for a given seed, so the prefix we skip equals what's already on disk.
    skipped = 0
    while skipped < len(existing):
        try:
            next(title_iter)
            skipped += 1
        except StopIteration:
            break

    fetched_this_run = 0
    for title in title_iter:
        if len(manifest) >= count:
            break
        if title in seen:
            continue
        try:
            text = _extract_plaintext(title)
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"[wiki-fetch]   skip {title!r}: {exc}", file=sys.stderr)
            time.sleep(sleep_seconds)
            continue
        if text is None:
            continue
        out_path = articles_dir / f"{_slug(title)}.txt"
        out_path.write_text(text, encoding="utf-8")
        manifest.append(title)
        seen.add(title)
        fetched_this_run += 1
        if fetched_this_run % 50 == 0:
            print(
                f"[wiki-fetch]   {len(manifest)}/{count} articles cached "
                f"(+{fetched_this_run} this run)",
                file=sys.stderr,
            )
            # Flush manifest periodically so a Ctrl-C doesn't lose progress.
            manifest_path.write_text("\n".join(manifest) + "\n", encoding="utf-8")
        time.sleep(sleep_seconds)

    manifest_path.write_text("\n".join(manifest) + "\n", encoding="utf-8")
    print(
        f"[wiki-fetch] done: {len(manifest)} articles in {cache_dir}",
        file=sys.stderr,
    )
    return manifest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bench.wiki_fetch",
        description="Fetch a deterministic snapshot of Wikipedia articles.",
    )
    parser.add_argument("--count", type=int, default=15_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("bench/wiki_cache"),
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=0.15,
        help="Inter-request delay. Wikipedia tolerates much faster, but "
        "0.15s keeps us comfortably below any threshold.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    fetch_snapshot(
        cache_dir=args.cache_dir,
        count=args.count,
        seed=args.seed,
        sleep_seconds=args.sleep_seconds,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
