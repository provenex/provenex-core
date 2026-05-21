# Supply chain

Provenex publishes the artifacts a security review will ask for. This
document tells you where to find them and how to verify them.

## What we publish per release

Every tag pushed to this repo (matching `v*`) triggers
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which
builds, signs, and publishes:

| Artifact | Where it lives | How to verify |
| --- | --- | --- |
| **sdist + wheel** | [PyPI release page](https://pypi.org/project/provenex-core/) | `pip install provenex-core==<version>` |
| **Sigstore-signed PEP 740 attestations** for sdist + wheel | Same PyPI release page (the "Provenance" panel) | `python -m sigstore verify identity --bundle <bundle.json> <artifact>` (see below) |
| **CycloneDX SBOM** (JSON) for the deployment-critical install | Attached to the corresponding GitHub Release as `sbom.cdx.json` | Open the JSON; it lists every transitive component with its name, version, and PURL |

## Why these specific signals

1. **Sigstore attestations on PyPI.** The wheel and sdist are signed via
   [PyPI's trusted publisher mechanism](https://docs.pypi.org/trusted-publishers/)
   using OIDC tokens minted by GitHub Actions on this repository. No
   long-lived PyPI API token exists in our secrets. A downstream
   consumer can verify the chain of custody from the signed artifact
   back to a specific commit + workflow run, without trusting our
   release notes or our maintainers' credentials.

2. **CycloneDX SBOM.** Compliance reviewers and procurement teams ask
   "what's in this package?" The SBOM answers that with a machine-
   readable component list. The version we publish covers the
   deployment-critical extras (`postgres`, `ed25519`, `policy`); the
   framework-integration extras (`langchain`, `langgraph`,
   `llamaindex`, `crewai`) are caller-driven and the consuming
   organization should generate their own SBOM that reflects their
   real install set.

3. **Zero hard dependencies in the core.** Read
   [`pyproject.toml`](../pyproject.toml): `dependencies = []`. The
   `provenex-core` library itself imports nothing outside the Python
   standard library. Every dependency you see in our SBOM is something
   you opted into via an extra. The smallest blast radius a Python
   library can offer for a supply-chain incident.

## Verifying a release locally

### Sigstore verify

```bash
# Install sigstore
pip install sigstore

# 1) Download the wheel from PyPI.
#    The PyPI "Provenance" panel for the release shows the download URL
#    for the wheel and links to its attestation bundle. Use whichever
#    file PyPI lists; the exact URLs change with each release.
pip download --no-deps provenex-core==X.Y.Z

# 2) Fetch the attestation bundle.
#    The bundle URL is documented under PyPI's PEP 740 attestations API.
#    See https://docs.pypi.org/attestations/ for the current endpoint; we
#    deliberately don't pin the URL here because PyPI's integrity API is
#    still maturing.

# 3) Verify the attestation against this repository's GitHub Actions identity.
python -m sigstore verify identity \
  --bundle provenex_core-X.Y.Z-py3-none-any.whl.publish.attestation \
  --cert-identity 'https://github.com/provenex/provenex-core/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
  --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
  provenex_core-X.Y.Z-py3-none-any.whl
```

A green verification proves: the wheel you have was built by the
`release.yml` workflow at the named tag, on this repository, by this
GitHub organization. Nobody else can produce a matching attestation.

### SBOM review

Download `sbom.cdx.json` from the GitHub Release page for the matching
version. Read it with any CycloneDX-aware tool, or inspect components
directly:

```bash
jq '.components[] | {name, version, purl}' sbom.cdx.json
```

The SBOM is generated from the real installed environment of the
release runner, not derived from a lock file. It reflects what was
actually present at build time.

## What we do NOT (yet) publish

* **SLSA Level 2+ build provenance.** On the roadmap, deferred until
  v1.1. PyPI's PEP 740 attestations give the equivalent identity
  binding for now; SLSA would add the reproducible-build hash
  verification that complements that.
* **Per-release vulnerability scan results.** Reviewers can run
  `pip-audit` against the published wheel locally; we do not check in
  a baseline.

If you need either of these as a procurement signal before we ship
them, reach out, we have prioritized them above other backlog items
when customers have asked.

## Reporting a supply-chain concern

Use the same channel as any security report: see
[`SECURITY.md`](../SECURITY.md). Supply-chain incidents (compromised
upstream dep, suspicious attestation, anomalous PyPI metadata) are
treated as high-priority.
