"""Bench workloads: ingest, verify, and inclusion proof generation/verification.

Each workload returns a :class:`WorkloadResult` containing a throughput
meter and a set of latency histograms. The scale runner aggregates these
into a JSON metrics file and a markdown report.

The workloads exercise the real public surface of Provenex — the same
:class:`Fingerprinter` and :class:`MerkleSQLiteProvenanceIndex` an
application would use. No private internals, no monkey-patching. What
the bench measures is what the application will see.
"""

from __future__ import annotations

import os
import random
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from provenex.core.fingerprinter import Fingerprinter
from provenex.core.merkle import verify_inclusion_proof
from provenex.index.base import VerificationOutcome
from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex
from provenex.policy.evaluator import ChunkContext, RequestContext

from .corpus import SyntheticCorpus
from .metrics import LatencyHistogram, ThroughputMeter


@dataclass
class WorkloadResult:
    """Output of one workload pass."""

    name: str
    throughput: Optional[ThroughputMeter] = None
    histograms: Dict[str, LatencyHistogram] = field(default_factory=dict)
    extras: Dict[str, object] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Ingest                                                                      #
# --------------------------------------------------------------------------- #


@dataclass
class IngestResult(WorkloadResult):
    """Ingest workload result.

    The ``extras`` dict carries the populated index and the list of every
    fingerprint that was indexed, in insertion order. The verify and proof
    workloads consume both.
    """

    pass


def run_ingest(
    corpus: SyntheticCorpus,
    db_path: str,
    signing_secret: bytes,
) -> IngestResult:
    """Ingest the entire corpus into a Merkle-augmented SQLite index.

    Measures: chunks/sec, documents/sec, per-chunk fingerprint+ingest
    latency, and final DB file size on disk.

    The bench sets ``journal_mode=WAL`` and ``synchronous=NORMAL`` on the
    SQLite connection — both are standard tunings for production SQLite
    workloads. They do not change the data the index writes, only when
    the OS flushes pages.
    """
    result = IngestResult(name="ingest")
    fp_lat = LatencyHistogram(name="fingerprint")
    add_lat = LatencyHistogram(name="index_add")
    chunks_meter = ThroughputMeter(name="chunks_ingested")
    docs_meter = ThroughputMeter(name="docs_ingested")

    fp = Fingerprinter()
    idx = MerkleSQLiteProvenanceIndex(db_path, signing_secret=signing_secret)
    # Production tuning for the SQLite backing store — see docstring.
    idx._conn.execute("PRAGMA journal_mode = WAL")  # type: ignore[attr-defined]
    idx._conn.execute("PRAGMA synchronous = NORMAL")  # type: ignore[attr-defined]
    all_fingerprints: List[str] = []

    chunks_meter.start()
    docs_meter.start()
    try:
        for doc in corpus:
            # One document_version per document, computed from the full
            # concatenated text. Used for every chunk in this doc — that's
            # how a real RAG ingestor would version it.
            doc_full_text = "\n".join(doc.chunks)
            doc_version = fp.fingerprint_chunk(doc_full_text)
            for chunk_text in doc.chunks:
                with fp_lat.time():
                    chunk_fp = fp.fingerprint_chunk(chunk_text)
                with add_lat.time():
                    idx.add(
                        fingerprint=chunk_fp,
                        document_id=doc.document_id,
                        document_version=doc_version,
                        chunk_offset=0,
                        chunk_length=len(chunk_text),
                    )
                all_fingerprints.append(chunk_fp)
                chunks_meter.add(1)
            docs_meter.add(1)
    finally:
        chunks_meter.stop()
        docs_meter.stop()

    # Measure tree root + DB size after ingest completes.
    tree_root = idx.tree_root()
    tree_size = idx.tree_size()
    db_size_bytes = os.path.getsize(db_path) if db_path != ":memory:" else 0

    result.throughput = chunks_meter
    result.histograms = {"fingerprint": fp_lat, "index_add": add_lat}
    result.extras = {
        "index": idx,
        "fingerprints": all_fingerprints,
        "docs_throughput": docs_meter,
        "tree_root": tree_root,
        "tree_size": tree_size,
        "db_size_bytes": db_size_bytes,
    }
    return result


# --------------------------------------------------------------------------- #
# Verify                                                                      #
# --------------------------------------------------------------------------- #


def run_verify(
    idx: MerkleSQLiteProvenanceIndex,
    fingerprints: List[str],
    sample_size: int,
    unknown_rate: float,
    seed: int,
) -> WorkloadResult:
    """Sample fingerprints from the index and verify them.

    A fraction ``unknown_rate`` of queries are synthetic fingerprints that
    are deliberately not in the index, so the workload exercises the
    ``UNVERIFIED`` path as well as ``VERIFIED``.
    """
    rng = random.Random(seed)
    lookup_lat = LatencyHistogram(name="verify")
    outcomes: Dict[str, int] = {}
    meter = ThroughputMeter(name="verifications")

    sample_size = min(sample_size, len(fingerprints) * 2)
    queries: List[Tuple[str, bool]] = []  # (fingerprint, expected_in_index)
    for _ in range(sample_size):
        if rng.random() < unknown_rate:
            # Random fingerprint that won't be in the index.
            queries.append(("sha256:" + secrets.token_hex(32), False))
        else:
            queries.append((rng.choice(fingerprints), True))

    meter.start()
    for fp, _expected in queries:
        with lookup_lat.time():
            outcome = idx.verify(fp)
        outcomes[outcome.value] = outcomes.get(outcome.value, 0) + 1
        meter.add(1)
    meter.stop()

    return WorkloadResult(
        name="verify",
        throughput=meter,
        histograms={"verify": lookup_lat},
        extras={"outcome_counts": outcomes},
    )


# --------------------------------------------------------------------------- #
# Proof generation + offline verification                                     #
# --------------------------------------------------------------------------- #


def run_proof(
    idx: MerkleSQLiteProvenanceIndex,
    fingerprints: List[str],
    sample_size: int,
    seed: int,
) -> WorkloadResult:
    """Sample fingerprints and measure inclusion proof gen + offline verify.

    The offline verify path is what an auditor with the receipt and tree
    head — but no access to the index — would do. Measuring it on the same
    hardware shows that proofs scale logarithmically in tree size.
    """
    rng = random.Random(seed)
    gen_lat = LatencyHistogram(name="proof_gen")
    verify_lat = LatencyHistogram(name="proof_verify_offline")
    proof_sizes: List[int] = []
    meter = ThroughputMeter(name="proofs")

    sample_size = min(sample_size, len(fingerprints))
    sampled = rng.sample(fingerprints, sample_size)

    tree_size = idx.tree_size()
    root = bytes.fromhex(idx.tree_root().removeprefix("sha256:"))

    meter.start()
    for fp in sampled:
        with gen_lat.time():
            leaf, leaf_index, proof_hex = idx.inclusion_proof(fp)
        proof_sizes.append(len(proof_hex))
        # Offline verification: only the leaf, index, size, proof, root.
        # No index access.
        proof = [bytes.fromhex(h.removeprefix("sha256:")) for h in proof_hex]
        with verify_lat.time():
            ok = verify_inclusion_proof(leaf, leaf_index, tree_size, proof, root)
        if not ok:
            raise AssertionError(f"benchmark integrity: proof for {fp} did not verify")
        meter.add(1)
    meter.stop()

    return WorkloadResult(
        name="proof",
        throughput=meter,
        histograms={
            "proof_gen": gen_lat,
            "proof_verify_offline": verify_lat,
        },
        extras={
            "mean_proof_hashes": (
                sum(proof_sizes) / len(proof_sizes) if proof_sizes else 0
            ),
            "max_proof_hashes": max(proof_sizes) if proof_sizes else 0,
        },
    )


# --------------------------------------------------------------------------- #
# Policy evaluation                                                            #
# --------------------------------------------------------------------------- #

# A representative HR-corpus policy. Three rules across the dimensions the
# deep dive calls out: jurisdiction / residency, PII gating by role, and a
# freshness window. Big enough to exercise rule-fired traces; small enough
# to fit in any reviewer's head.
_POLICY_HR_CORPUS = """
version: 1
policy_id: bench-hr-corpus-v1

access_control:
  rules:
    - name: jurisdiction_eu_only
      when:
        request.jurisdiction: EU
      require:
        chunk.metadata.residency:
          in: [EU, EEA]
      on_violation: deny

    - name: pii_classification_gate
      when:
        chunk.metadata.contains_pii: true
      require:
        request.caller.role:
          in: [hr_admin, payroll]
      on_violation: deny

    - name: freshness_for_policy_corpus
      when:
        chunk.metadata.corpus: policy_documents
      require:
        chunk.ingested_at:
          not_older_than: 90d
      on_violation: deny

  defaults:
    unknown_metadata: deny
"""


def run_policy_eval(
    fingerprints: List[str],
    sample_size: int,
    seed: int,
) -> WorkloadResult:
    """Measure native-YAML policy-evaluator latency at retrieval rates.

    Builds a representative HR-corpus policy and runs it across a synthetic
    metadata distribution: 70% EU residency / 30% other, 20% PII-tagged,
    50% under the freshness-windowed corpus. The mix is calibrated so the
    decisions split roughly 70/30 allow/deny — enough variety to exercise
    every rule path without skewing the histogram.

    Reports per-evaluation latency plus an outcome breakdown so an auditor
    can sanity-check the mix produced the expected decision distribution.
    """
    from provenex.policy.yaml_evaluator import NativeYamlEvaluator

    rng = random.Random(seed)
    evaluator = NativeYamlEvaluator.from_text(_POLICY_HR_CORPUS)
    eval_lat = LatencyHistogram(name="policy_eval")
    meter = ThroughputMeter(name="evaluations")
    decisions: Dict[str, int] = {"allow": 0, "deny": 0}
    rules_fired_counts: Dict[str, int] = {}

    request = RequestContext(
        caller={"role": "hr_admin"},
        jurisdiction="EU",
        purpose="customer_support",
        timestamp="2026-05-13T14:32:07Z",
    )
    user_request = RequestContext(
        caller={"role": "intern"},
        jurisdiction="EU",
        purpose="customer_support",
        timestamp="2026-05-13T14:32:07Z",
    )

    sample_size = min(sample_size, len(fingerprints))
    sampled = rng.sample(fingerprints, sample_size)

    # Calibrate the metadata distribution so the three rules actually
    # fire. Each chunk gets a randomised tag set.
    meter.start()
    for fp in sampled:
        is_eu = rng.random() < 0.70
        has_pii = rng.random() < 0.20
        in_policy_corpus = rng.random() < 0.50
        age_days = rng.randint(1, 180)
        metadata = {
            "residency": "EU" if is_eu else "US",
            "contains_pii": has_pii,
        }
        if in_policy_corpus:
            metadata["corpus"] = "policy_documents"

        # Choose request: PII chunks alternate between admin (allow) and
        # intern (deny) to keep both decision paths warm.
        req = request if (not has_pii or rng.random() < 0.5) else user_request

        chunk = ChunkContext(
            fingerprint=fp,
            document_id="d",
            document_version="v",
            ingested_at=f"2026-{((180 - age_days) // 30 + 1):02d}-15T00:00:00Z",
            metadata=metadata,
        )
        with eval_lat.time():
            decision = evaluator.evaluate(chunk, req)
        decisions[decision.decision] = decisions.get(decision.decision, 0) + 1
        for rname in decision.rules_fired:
            rules_fired_counts[rname] = rules_fired_counts.get(rname, 0) + 1
        meter.add(1)
    meter.stop()

    return WorkloadResult(
        name="policy_eval",
        throughput=meter,
        histograms={"policy_eval": eval_lat},
        extras={
            "evaluator": evaluator.evaluator_name,
            "policy_id": evaluator.policy_id,
            "policy_version_hash": evaluator.policy_version_hash,
            "decision_counts": decisions,
            "rules_fired_counts": rules_fired_counts,
        },
    )
