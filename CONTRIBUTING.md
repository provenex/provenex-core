# Contributing to provenex-core

Thanks for considering a contribution. This document covers the load-bearing conventions and the practical steps to get a change merged. Smaller items (style, formatting) are governed by tooling; the substantive items below are the ones that matter for the security and audit properties Provenex makes.

## Before you start

- **Issues vs Discussions.** File a [GitHub issue](https://github.com/provenex/provenex-core/issues) for bugs, feature proposals with clear acceptance criteria, and documentation gaps. Start a [GitHub Discussion](https://github.com/provenex/provenex-core/discussions) for open-ended questions, integration help, or "is this the right approach" conversations.
- **Security issues.** Do not file these in public. See [SECURITY.md](SECURITY.md); send to `contact@provenex.ai`.
- **Larger changes.** Open an issue first describing the proposed approach. Multi-day work that lands as a surprise PR is harder to merge than the same work pre-aligned.

## Load-bearing conventions

These are not style choices; breaking them breaks security or audit properties Provenex commits to externally.

**Stdlib-only in the core.** The `provenex/` package (excluding `provenex/integrations/`, `provenex/tool_call/integrations/`, and `provenex/export/`) is pure Python standard library. The `dependencies = []` line in [pyproject.toml](pyproject.toml) is the contract. Third-party imports go behind optional extras and lazy import inside the integration module. A change that adds a top-level `import some_third_party` to the core will be reverted.

**Test-first on core algorithms.** Changes to the fingerprinter, normalizer, hasher, index implementations, policy evaluator, receipt builder, signer interface, Merkle tree, or witness log land with tests first. The expected pattern: a failing test that pins the new behavior, then the implementation that makes it pass. Red-team tests (`tests/test_window_splice_redteam.py`, `tests/test_outcome_precedence.py`, `tests/test_request_binding.py`, `tests/test_peppered_fingerprint.py`, `tests/test_witness_log.py`) are not optional; they are part of the surface those modules expose.

**The five verification outcomes are sacred.** `VERIFIED`, `STALE`, `UNAUTHORIZED`, `UNVERIFIED`, `TAMPERED`. Adding a sixth outcome, renaming one, or weakening the precedence (`TAMPERED > UNAUTHORIZED > STALE > UNVERIFIED > VERIFIED`, codified as `OUTCOME_PRECEDENCE` in [provenex/index/base.py](provenex/index/base.py)) is a documented-bump change, not a routine PR. Open an issue first and expect a longer discussion than feature work usually requires.

**Receipt schema is authoritative; changes go through the documented bump path.** `SCHEMA_VERSION` lives in [provenex/core/receipt.py](provenex/core/receipt.py) and is the single source of truth. Minor bumps must be additive on the wire (a verifier built against the prior minor must still validate the new version when it ignores unknown fields). Major bumps must be justified and propagate to [docs/receipt_format.md § Schema history](docs/receipt_format.md). Every PR that touches `SCHEMA_VERSION` must update the schema-history table in the same commit; the `scripts/check_docs_consistency.py` lint catches this.

**No silent canonicalisation changes.** The canonical signing payload, the `inputs_hash` payload, the `caller_hash` payload, and every other hash on the receipt are governed by one rule: `json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. Changing any part of that rule changes the signature on every receipt the binary produces. Such a change is a breaking change to the auditor's tools and must land with a major version bump.

**Smart quotes survive.** Receipt prose, doc prose, and policy rule names may contain non-ASCII characters (smart quotes, accented characters, CJK in caller dicts). The canonical-JSON rule pins `ensure_ascii=False` precisely so this content round-trips across language boundaries. Do not introduce code that normalises non-ASCII characters away in user-facing data.

## Style

- **Formatting** is governed by `ruff` and `black`, both configured in [pyproject.toml](pyproject.toml). Run `ruff check .` and `black .` before opening a PR. There is no separate prose style guide for code; if it passes `ruff` and `black`, it passes.
- **Type hints** are encouraged on public surfaces; `mypy>=1.10` runs in CI.
- **Comments.** Default to writing no comments. Add one when the WHY is non-obvious (a workaround for a specific bug, a hidden invariant, behavior that would surprise a reader). Do not narrate what the code does; well-named identifiers do that.
- **No em-dashes** (`U+2014`) in newly written prose. Use commas, parentheses, semicolons, colons, or sentence breaks. This applies to documentation, code comments, commit messages, and PR descriptions.
- **Commit messages** are short, generic, and free of strategic detail. The CHANGELOG is the customer-facing summary; commit messages do not need to repeat it.

## Running the test suite

```bash
pip install -e ".[dev,postgres,policy,ed25519,langchain,langgraph,llamaindex,crewai]"
pytest -q
```

The full suite runs against a real Postgres if `PROVENEX_TEST_POSTGRES_DSN` is set; without it, the Postgres-tagged tests skip. CI runs both modes.

After substantive changes to the core, also run:

```bash
provenex selftest
```

`provenex selftest` is the in-process conformance check that re-derives every load-bearing property the docs claim against the installed binary. A PR that breaks `selftest` will not merge.

The docs-consistency lint runs as part of the test suite via `tests/test_docs_consistency.py`; it can also be invoked directly:

```bash
python scripts/check_docs_consistency.py
```

This catches drift between the source-of-truth `SCHEMA_VERSION` and `ISSUER` strings in [provenex/core/receipt.py](provenex/core/receipt.py) and every doc that quotes them.

## Sign-off (DCO)

Provenex requires the [Developer Certificate of Origin](https://developercertificate.org/) on every commit. There is no CLA. Add `-s` to your commit command:

```bash
git commit -s -m "your message"
```

The DCO does not assign copyright; the contributor retains ownership and licenses the contribution under MIT to the project.

## PR review

PRs are reviewed by the maintainers at [contact@provenex.ai](mailto:contact@provenex.ai). Review focus, in priority order:

1. Does the change preserve the load-bearing conventions above?
2. Does it include tests for any behavior change?
3. Does it touch `SCHEMA_VERSION`, `OUTCOME_PRECEDENCE`, or any canonicalisation rule? If so, is the bump rationale documented?
4. Does the docs-consistency lint pass?
5. Is the docstring or doc update accurate against the code?

Smaller items (line length, typo, naming consistency) are addressed inline and do not block.

## Read next

- [SECURITY.md](SECURITY.md): vulnerability reporting policy.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): community standards.
- [docs/how_it_works.md](docs/how_it_works.md): the algorithm walkthrough. Read this before changing any of the core surface.
- [docs/threat_model.md](docs/threat_model.md): the attacker model that the load-bearing conventions above are calibrated against.
- [docs/receipt_format.md](docs/receipt_format.md): the wire schema and the schema-history table that schema bumps update.
