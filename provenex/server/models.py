"""Pydantic request/response models for the Provenex HTTP API.

Keep these as flat and JSON-shaped as possible. They are the wire
contract; any non-Python client (Java, Go, Rust, Node) reads the
OpenAPI spec from ``docs/openapi/openapi.json`` and codegens types
against these models.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Shared sub-models                                                           #
# --------------------------------------------------------------------------- #


class RequestContextBody(BaseModel):
    """Wire shape for :class:`RequestContext`.

    Shared between /v1/verify and /v1/admit/* so the same JSON dict
    works on both surfaces.
    """

    caller: Dict[str, Any] = Field(default_factory=dict)
    jurisdiction: Optional[str] = None
    purpose: Optional[str] = None
    timestamp: Optional[str] = None
    session_id: Optional[str] = None


class ToolCallBody(BaseModel):
    """Subset of :class:`ToolCallContext` needed over the wire."""

    name: str
    operation: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    target_system: Optional[str] = None
    invocation_id: Optional[str] = None


# --------------------------------------------------------------------------- #
# /v1/verify                                                                  #
# --------------------------------------------------------------------------- #


class VerifyRequest(BaseModel):
    """POST /v1/verify request body."""

    chunks: List[str] = Field(
        ..., description="Retrieved chunk texts. Verified against the index."
    )
    request_text: Optional[str] = Field(
        None,
        description=(
            "Optional triggering query / prompt text. Hashed onto the receipt's "
            "request_binding.query_hash so a valid receipt cannot be presented "
            "as evidence for a different query. The text itself is not "
            "recorded."
        ),
    )
    request: Optional[RequestContextBody] = Field(
        None,
        description=(
            "Optional RequestContext: caller identity, jurisdiction, "
            "purpose, timestamp, session_id. Required when the loaded policy "
            "has access_control set; otherwise optional. Same shape as the "
            "request body on /v1/admit/*."
        ),
    )
    output_text: str = Field(
        "",
        description=(
            "Optional LLM output text whose hash is recorded on the receipt. "
            "Pass on the final call in a multi-step flow."
        ),
    )


class VerifyResponse(BaseModel):
    """POST /v1/verify response body."""

    kept: List[str] = Field(..., description="Chunk texts that passed policy.")
    blocked: List[str] = Field(..., description="Chunks removed by policy.")
    receipt: Dict[str, Any] = Field(
        ..., description="The signed provenance receipt as a JSON object."
    )


# --------------------------------------------------------------------------- #
# /v1/admit/*                                                                 #
# --------------------------------------------------------------------------- #


class AdmitToolRequest(BaseModel):
    """POST /v1/admit/tool request body."""

    tool: ToolCallBody
    request: RequestContextBody
    redact_parameters: bool = False
    redact_inputs: bool = False


class AdmitMemoryWriteRequest(BaseModel):
    """POST /v1/admit/memory_write request body."""

    memory_key: str = Field(..., description="The memory key being written.")
    value: Any = Field(..., description="The value being written. Hashed.")
    store_id: Optional[str] = Field(
        None, description="Optional memory store / namespace id."
    )
    request: RequestContextBody


class AdmitModelInferenceRequest(BaseModel):
    """POST /v1/admit/model_inference request body."""

    model_name: str = Field(..., description="Model identifier, e.g. claude-opus-4-7.")
    prompt: Any = Field(..., description="Prompt text. Hashed on the receipt.")
    target_provider: Optional[str] = Field(None, description="Provider, e.g. anthropic.")
    request: RequestContextBody


class AdmissionResponse(BaseModel):
    """Shared response shape for the /v1/admit/* family."""

    decision: str = Field(..., description="`allow` or `deny`.")
    rules_fired: List[str] = Field(default_factory=list)
    receipt: Dict[str, Any]


# --------------------------------------------------------------------------- #
# /v1/ingest                                                                  #
# --------------------------------------------------------------------------- #


class IngestEntry(BaseModel):
    """One chunk to ingest into the Postgres index."""

    fingerprint: str = Field(
        ...,
        description="SHA-256 fingerprint in canonical form: `sha256:<hex>`.",
    )
    document_id: str
    document_version: str = Field(
        ...,
        description="`sha256:<hex>` over the normalized document.",
    )
    chunk_offset: int = Field(0, ge=0)
    chunk_length: int = Field(..., ge=0)
    authorized: bool = True
    entry_kind: str = Field(
        "whole_chunk", description="Either `whole_chunk` or `window`."
    )


class IngestRequest(BaseModel):
    """POST /v1/ingest request body."""

    entries: List[IngestEntry]


class IngestResponse(BaseModel):
    """POST /v1/ingest response body."""

    ingested: int
