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
| **Multi-arch container image** (linux/amd64 + linux/arm64) | `ghcr.io/provenex/provenex-server:<version>` | `cosign verify ghcr.io/provenex/provenex-server:<version> --certificate-identity '...' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'` (see below) |
| **SLSA build provenance + image SBOM** for the container | Attached to the manifest list via buildx (`provenance: mode=max`, `sbom: true`) | `cosign verify-attestation --type slsaprovenance ...` or pull via `docker buildx imagetools inspect` |

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

* **Reproducible builds.** The Sigstore attestation is an *identity*
  attestation: it binds the wheel hash to a specific GitHub Actions
  workflow run, a specific commit, and the `provenex-core` repository.
  It does **not** prove that a third party building the same source
  tarball locally would produce the same wheel byte-for-byte. True
  reproducible build requires pinning Python build tool versions,
  setting `SOURCE_DATE_EPOCH` for deterministic timestamps, and
  documenting the exact build environment so a reviewer can match it.
  We have not done this work yet. The destination is SLSA Level 3
  with build provenance; tracked for v1.1.
* **SLSA Level 2+ build provenance.** Deferred to v1.1. PyPI's PEP 740
  attestations give identity binding today; SLSA L3 adds the
  reproducible-build hash verification that complements it.
* **Per-release vulnerability scan results.** Reviewers can run
  `pip-audit` against the published wheel locally; we do not check in
  a baseline.

If you need either of these as a procurement signal before we ship
them, reach out, we have prioritized them above other backlog items
when customers have asked.

## PyPI typosquat awareness

Two project names on PyPI are owned by us:

| Name | Purpose |
| --- | --- |
| `provenex-core` | The canonical library. This is the one customers should install. |
| `provenex` | Thin meta-package that installs `provenex-core` as its only dependency. Intended for users who type the obvious name; provided so it is not available to typosquatters. |

Any other PyPI project name that contains "provenex" is **not from
us**. Names that look plausible but are not ours:

* `provenex-sdk`, `provenex-client`, `provenex-py`, `provenex-ai`,
  `provenex-rag`, `py-provenex`, `provenex_core` (with an underscore
  in the slug), `provenex-cli`, `provenex-tools`.

We are working through claiming these as defensive placeholders.
Until that is complete, **only install from `provenex-core` or
`provenex`** and verify the project URL on PyPI points to
`https://github.com/provenex/provenex-core` before trusting any
install. Reporting a typosquat: use the disclosure channel in
[`SECURITY.md`](../SECURITY.md).

## Verifying the v0.10.0 release

The first release with the full supply-chain signal chain (Sigstore
attestations + CycloneDX SBOM + trusted-publisher OIDC) is v0.10.0.
To confirm the release on PyPI matches the source on GitHub:

```bash
# 1. Pull the wheel from PyPI.
pip download --no-deps provenex-core==0.10.0

# 2. View the "Provenance" panel on the PyPI release page:
#    https://pypi.org/project/provenex-core/0.10.0/
#    It will show the GitHub Actions workflow run that produced the
#    attestation, the OIDC issuer claims (repo, ref, workflow), and a
#    link to the Sigstore Rekor log entry.

# 3. Download the SBOM from the matching GitHub Release:
#    https://github.com/provenex/provenex-core/releases/tag/v0.10.0
#    The asset is `sbom.cdx.json` (CycloneDX 1.6).

# 4. Optional: verify the attestation locally with sigstore.
#    See https://docs.pypi.org/attestations/ for the current API
#    surface; the bundle URL pattern is still maturing.
pip install sigstore
python -m sigstore verify identity \
  --cert-identity 'https://github.com/provenex/provenex-core/.github/workflows/release.yml@refs/tags/v0.10.0' \
  --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
  provenex_core-0.10.0-py3-none-any.whl
```

A green verification means the wheel you have was built by the
`release.yml` workflow at tag `v0.10.0` on this repository, by this
GitHub organization. No party outside that chain can produce a
matching attestation.

### Verifying the container image

```bash
# 1. Install cosign.
brew install cosign  # macOS; see https://docs.sigstore.dev/cosign/ for others

# 2. Verify the image's keyless Sigstore signature. The cert-identity
#    encodes the workflow file path + git ref; only the GitHub Actions
#    OIDC identity for our release.yml at that tag can sign matching
#    the constraint below.
cosign verify ghcr.io/provenex/provenex-server:0.10.0 \
  --certificate-identity 'https://github.com/provenex/provenex-core/.github/workflows/release.yml@refs/tags/v0.10.0' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

# 3. Optional: inspect the SLSA build provenance attached to the image.
cosign verify-attestation --type slsaprovenance \
  --certificate-identity 'https://github.com/provenex/provenex-core/.github/workflows/release.yml@refs/tags/v0.10.0' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/provenex/provenex-server:0.10.0

# 4. Optional: pull the SBOM that buildx attached.
docker buildx imagetools inspect ghcr.io/provenex/provenex-server:0.10.0 --format '{{ json . }}'
```

A green verification on step 2 establishes that the image at this tag
was produced by our `release.yml` workflow at the corresponding git
tag. The attestation chain replaces the role a static signing key
would play in older release pipelines.

## Reporting a supply-chain concern

Use the same channel as any security report: see
[`SECURITY.md`](../SECURITY.md). Supply-chain incidents (compromised
upstream dep, suspicious attestation, anomalous PyPI metadata) are
treated as high-priority.
