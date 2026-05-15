"""Tests for the 0.6.5 step_kind coverage convenience entrypoints.

Covers:

    * compute_value_hash canonicalisation for strings / bytes / dicts /
      lists. Key reorder for dict inputs produces the same hash.
    * caller_hash salt: bare SHA-256 prefix when no salt; HMAC-SHA256
      prefix when supplied. Different salts produce different hashes;
      same salt + same caller reproduces.
    * verify_memory: sets step_kind="memory_read" and
      content_source="memory_store" on every source by default,
      overridable by caller.
    * admit_memory_write: name="memory.write", operation=<memory_key>,
      value_hash always present, verbatim value redacted by default
      and recorded when redact_value=False; step_kind="memory_write".
    * admit_model_inference: name=<model>, operation="complete" by
      default, target_system=<provider>, prompt_hash always present,
      verbatim prompt redacted by default; step_kind="model_inference".
    * Signature still verifies for every new entrypoint.
"""

from __future__ import annotations

import json

from provenex import (
    HmacSha256Signer,
    Policy,
    RequestContext,
    SQLiteProvenanceIndex,
    admit_memory_write,
    admit_model_inference,
    compute_caller_hash,
    compute_value_hash,
    start_trajectory,
    verify_memory,
)
from provenex.core.receipt import verify_receipt_signature


SECRET = b"test-step-kind-coverage-secret"


def _make_index(tmp_path) -> SQLiteProvenanceIndex:
    return SQLiteProvenanceIndex(str(tmp_path / "p.db"), signing_secret=SECRET)


def _signer() -> HmacSha256Signer:
    return HmacSha256Signer(secret=SECRET)


def _request(session_id: str | None = None) -> RequestContext:
    return RequestContext(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
        session_id=session_id,
    )


# ---------- compute_value_hash ---------- #


def test_compute_value_hash_string_stable():
    a = compute_value_hash("hello world")
    b = compute_value_hash("hello world")
    assert a == b
    assert a.startswith("sha256:")
    assert len(a) == len("sha256:") + 64


def test_compute_value_hash_dict_stable_across_key_order():
    a = compute_value_hash({"id": 1, "role": "engineer"})
    b = compute_value_hash({"role": "engineer", "id": 1})
    assert a == b


def test_compute_value_hash_distinguishes_values():
    assert compute_value_hash("a") != compute_value_hash("b")
    assert compute_value_hash({"k": 1}) != compute_value_hash({"k": 2})


def test_compute_value_hash_bytes_match_string():
    assert compute_value_hash("hello") == compute_value_hash(b"hello")


def test_compute_value_hash_messages_list():
    msgs = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
    ]
    h1 = compute_value_hash(msgs)
    h2 = compute_value_hash(list(msgs))
    assert h1 == h2


# ---------- caller_hash salt ---------- #


def test_caller_hash_unsalted_uses_sha256_prefix():
    h = compute_caller_hash({"id": "u_1"})
    assert h.startswith("sha256:")


def test_caller_hash_salted_uses_hmac_prefix():
    h = compute_caller_hash({"id": "u_1"}, salt=b"deployment-A")
    assert h.startswith("hmac-sha256:")


def test_caller_hash_different_salts_produce_different_hashes():
    a = compute_caller_hash({"id": "u_1"}, salt=b"deployment-A")
    b = compute_caller_hash({"id": "u_1"}, salt=b"deployment-B")
    assert a != b


def test_caller_hash_same_salt_reproducible():
    a = compute_caller_hash({"id": "u_1"}, salt=b"deployment-A")
    b = compute_caller_hash({"id": "u_1"}, salt=b"deployment-A")
    assert a == b


def test_caller_hash_salted_emitted_on_receipt():
    req = _request()
    from provenex import admission_check, ToolCallContext

    r = admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=req,
        signer=_signer(),
        caller_hash_salt=b"deployment-A",
    )
    d = r.receipt.to_dict()
    assert d["caller_hash"].startswith("hmac-sha256:")
    expected = compute_caller_hash(req.caller, salt=b"deployment-A")
    assert d["caller_hash"] == expected


# ---------- verify_memory ---------- #


def test_verify_memory_sets_step_kind_memory_read(tmp_path):
    idx = _make_index(tmp_path)
    trj = start_trajectory(agent_id="a")
    r = verify_memory(
        ["agent memory entry"],
        idx,
        signer=_signer(),
        request_context=_request(),
        trajectory=trj,
    )
    assert r.receipt.to_dict()["trajectory"]["step_kind"] == "memory_read"


def test_verify_memory_sets_content_source_memory_store(tmp_path):
    idx = _make_index(tmp_path)
    r = verify_memory(
        ["agent memory entry"],
        idx,
        signer=_signer(),
        request_context=_request(),
    )
    assert r.receipt.to_dict()["sources"][0]["content_source"] == "memory_store"


def test_verify_memory_caller_can_override_defaults(tmp_path):
    idx = _make_index(tmp_path)
    trj = start_trajectory(agent_id="a")
    r = verify_memory(
        ["x"],
        idx,
        signer=_signer(),
        request_context=_request(),
        trajectory=trj,
        step_kind="memory_read_eviction_pass",
        content_source="indexed_corpus",
    )
    d = r.receipt.to_dict()
    assert d["trajectory"]["step_kind"] == "memory_read_eviction_pass"
    assert d["sources"][0]["content_source"] == "indexed_corpus"


# ---------- admit_memory_write ---------- #


def test_admit_memory_write_basic_shape():
    trj = start_trajectory(agent_id="a")
    r = admit_memory_write(
        memory_key="user_profile",
        value={"last_message": "hello"},
        request=_request(),
        store_id="crewai_memory",
        signer=_signer(),
        trajectory=trj,
    )
    d = r.receipt.to_dict()
    assert d["actions"][0]["name"] == "memory.write"
    assert d["actions"][0]["operation"] == "user_profile"
    assert d["actions"][0]["target_system"] == "crewai_memory"
    assert d["actions"][0]["parameters"]["value_hash"].startswith("sha256:")
    assert d["actions"][0]["parameters"]["store_id"] == "crewai_memory"
    # Default: verbatim value redacted.
    assert "value" not in d["actions"][0]["parameters"]
    assert d["trajectory"]["step_kind"] == "memory_write"


def test_admit_memory_write_records_value_when_not_redacted():
    r = admit_memory_write(
        memory_key="public_setting",
        value="dark_mode",
        request=_request(),
        signer=_signer(),
        redact_value=False,
    )
    d = r.receipt.to_dict()
    assert d["actions"][0]["parameters"]["value"] == "dark_mode"
    # value_hash always present.
    assert d["actions"][0]["parameters"]["value_hash"].startswith("sha256:")


def test_admit_memory_write_extra_parameters_preserved():
    r = admit_memory_write(
        memory_key="cache",
        value={"k": "v"},
        request=_request(),
        signer=_signer(),
        ttl=300,
        extra_parameters={"priority": "high"},
    )
    p = r.receipt.to_dict()["actions"][0]["parameters"]
    assert p["ttl"] == 300
    assert p["priority"] == "high"


def test_admit_memory_write_value_hash_independently_recomputable():
    value = {"chat_history": ["hi", "hello"]}
    r = admit_memory_write(
        memory_key="session",
        value=value,
        request=_request(),
        signer=_signer(),
    )
    on_receipt = r.receipt.to_dict()["actions"][0]["parameters"]["value_hash"]
    rederived = compute_value_hash(value)
    assert on_receipt == rederived


# ---------- admit_model_inference ---------- #


def test_admit_model_inference_basic_shape():
    trj = start_trajectory(agent_id="a")
    r = admit_model_inference(
        model_name="claude-opus-4-7",
        prompt="Summarize this incident",
        request=_request(),
        target_provider="anthropic",
        signer=_signer(),
        trajectory=trj,
    )
    d = r.receipt.to_dict()
    assert d["actions"][0]["name"] == "claude-opus-4-7"
    assert d["actions"][0]["operation"] == "complete"
    assert d["actions"][0]["target_system"] == "anthropic"
    assert d["actions"][0]["parameters"]["prompt_hash"].startswith("sha256:")
    # Default: verbatim prompt redacted.
    assert "prompt" not in d["actions"][0]["parameters"]
    assert d["trajectory"]["step_kind"] == "model_inference"


def test_admit_model_inference_messages_list_prompt():
    messages = [
        {"role": "user", "content": "What is INC-001?"},
        {"role": "assistant", "content": "An incident."},
    ]
    r = admit_model_inference(
        model_name="claude-opus-4-7",
        prompt=messages,
        request=_request(),
        target_provider="anthropic",
        signer=_signer(),
    )
    on_receipt = r.receipt.to_dict()["actions"][0]["parameters"]["prompt_hash"]
    rederived = compute_value_hash(messages)
    assert on_receipt == rederived


def test_admit_model_inference_records_prompt_when_not_redacted():
    r = admit_model_inference(
        model_name="claude-opus-4-7",
        prompt="non-sensitive prompt",
        request=_request(),
        signer=_signer(),
        redact_prompt=False,
    )
    p = r.receipt.to_dict()["actions"][0]["parameters"]
    assert p["prompt"] == "non-sensitive prompt"
    assert p["prompt_hash"].startswith("sha256:")


def test_admit_model_inference_operation_override():
    r = admit_model_inference(
        model_name="text-embedding-3-small",
        prompt="vectorize this",
        request=_request(),
        target_provider="openai",
        operation="embed",
        signer=_signer(),
    )
    assert r.receipt.to_dict()["actions"][0]["operation"] == "embed"


def test_admit_model_inference_extra_parameters_preserved():
    r = admit_model_inference(
        model_name="claude-opus-4-7",
        prompt="x",
        request=_request(),
        signer=_signer(),
        extra_parameters={"max_tokens": 4000, "temperature": 0.2},
    )
    p = r.receipt.to_dict()["actions"][0]["parameters"]
    assert p["max_tokens"] == 4000
    assert p["temperature"] == 0.2


# ---------- session_id flows through all three entrypoints ---------- #


def test_session_id_flows_through_new_entrypoints(tmp_path):
    idx = _make_index(tmp_path)
    trj = start_trajectory(agent_id="a", session_id="sess-1")
    req = _request(session_id="sess-1")
    signer = _signer()

    r1 = verify_memory(
        ["m"], idx, signer=signer, request_context=req, trajectory=trj
    )
    assert r1.receipt.to_dict()["trajectory"]["session_id"] == "sess-1"

    r2 = admit_memory_write(
        memory_key="k", value="v",
        request=req, signer=signer, trajectory=r1.next_trajectory,
    )
    assert r2.receipt.to_dict()["trajectory"]["session_id"] == "sess-1"

    r3 = admit_model_inference(
        model_name="m", prompt="p",
        request=req, signer=signer, trajectory=r2.next_trajectory,
    )
    assert r3.receipt.to_dict()["trajectory"]["session_id"] == "sess-1"


# ---------- signature still verifies ---------- #


def test_signature_covers_all_three_entrypoints(tmp_path):
    idx = _make_index(tmp_path)
    signer = _signer()
    req = _request()

    r1 = verify_memory(["m"], idx, signer=signer, request_context=req)
    assert verify_receipt_signature(json.loads(r1.receipt.to_json()), signer)

    r2 = admit_memory_write(memory_key="k", value="v", request=req, signer=signer)
    assert verify_receipt_signature(json.loads(r2.receipt.to_json()), signer)

    r3 = admit_model_inference(
        model_name="m", prompt="p", request=req, signer=signer
    )
    assert verify_receipt_signature(json.loads(r3.receipt.to_json()), signer)


# ---------- postgres backend encoding hardening ---------- #


def test_postgres_backend_sets_client_encoding_utf8(tmp_path):
    """The backend's configure callback should force UTF8 on every conn."""
    import os
    import pytest

    dsn = os.environ.get("PROVENEX_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("PROVENEX_TEST_POSTGRES_DSN not set")

    import psycopg
    from provenex import PostgresProvenanceIndex

    # Construct an index — this opens the pool and runs configure on
    # every connection.
    idx = PostgresProvenanceIndex(dsn=dsn, signing_secret=SECRET)
    try:
        with idx._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SHOW client_encoding")
                row = cur.fetchone()
                assert row[0] == "UTF8"
    finally:
        idx._pool.close()
