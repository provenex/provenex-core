"""Unified :class:`Policy` wrapper.

Schema 2.0.0 unified the verification gate and the data-access gate under
a single top-level ``policy`` block on the receipt. Schema 2.2.0 (Phase
2) adds a third half — ``tool_call_control`` — for admission decisions
on agentic tool calls. The Python API mirrors that shape: callers
construct one :class:`Policy` carrying all three halves, and pass it to
:func:`provenex.verify_chunks` and/or
:func:`provenex.tool_call.admission_check`.

Three halves:

* ``verification`` — :class:`VerificationPolicy` controlling which of the
  five outcomes (VERIFIED / STALE / UNAUTHORIZED / UNVERIFIED / TAMPERED)
  block a chunk before it reaches the next stage. Applies to retrieved
  content only.
* ``access_control`` — an optional :class:`PolicyEvaluator` that runs
  declarative rules over chunk metadata and the request context.
  Applies to retrieved content only.
* ``tool_call_control`` — an optional
  :class:`provenex.tool_call.ToolCallPolicyEvaluator` that runs
  declarative rules over tool-call parameters and the request context.
  Applies to agentic tool calls only.

A chunk reaches the LLM only if both retrieval-side halves allow it. A
tool call is admitted only if the tool-call half allows it. The
verification half is always present (with sensible defaults if the
caller doesn't override). The access-control and tool-call-control
halves are independent — early-stage deployments can ship verification
only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, TYPE_CHECKING

from .availability import IndexAvailabilityPolicy
from .evaluator import PolicyEvaluator
from .policy import VerificationPolicy

if TYPE_CHECKING:  # pragma: no cover — type hints only
    from ..tool_call.evaluator import ToolCallPolicyEvaluator

# Reserved top-level YAML keys for the unified config file. Anything else
# at the top level raises a parse error — the convention is "load loud,
# fail loud" so typos can't silently allow.
_UNIFIED_YAML_TOP_KEYS = frozenset(
    {
        "version",
        "policy_id",
        "description",
        "verification",
        "access_control",
        # Schema 2.2.0 addition: rules for tool-call admission.
        "tool_call_control",
        # v0.10 addition: operator-controlled behavior when the
        # provenance index is unreachable on the verify hot path.
        "availability",
    }
)


@dataclass(frozen=True)
class Policy:
    """The single policy object the caller passes to retrieval and admission.

    Attributes:
        verification: The five-outcome verification gate config. Defaults
            to :class:`VerificationPolicy` defaults (block UNAUTHORIZED
            and TAMPERED; flag everything else).
        access_control: Optional :class:`PolicyEvaluator` running
            declarative access-control rules over chunks. ``None`` means
            no chunk-access policy is in effect — only the verification
            gate applies, and the receipt's ``policy.access_control``
            block is omitted.
        tool_call_control: Optional
            :class:`provenex.tool_call.ToolCallPolicyEvaluator` running
            declarative admission rules over tool calls. ``None`` means
            no tool-call policy is in effect — admission allows by
            default, and the receipt's ``policy.tool_call_control``
            block is omitted. Schema 2.2.0+.
    """

    verification: VerificationPolicy = field(default_factory=VerificationPolicy)
    access_control: Optional[PolicyEvaluator] = None
    tool_call_control: Optional["ToolCallPolicyEvaluator"] = None
    availability: IndexAvailabilityPolicy = field(
        default_factory=IndexAvailabilityPolicy
    )

    @classmethod
    def from_yaml(cls, path: str) -> "Policy":
        """Load a unified Provenex policy file.

        File layout::

            version: 1
            policy_id: hr-corpus-v3        # optional but recommended
            description: ...               # optional

            verification:                  # optional; defaults if omitted
              block_stale: false
              block_unauthorized: true
              ...

            access_control:                # optional; allow-all if omitted
              rules:
                - name: ...
                  when: { ... }
                  require: { ... }
                  on_violation: deny
              defaults:
                unknown_metadata: deny
                policy_version_mismatch: deny

        Either subsection can be omitted. A file with neither produces a
        Policy with default verification and no access control — the
        equivalent of the v0.3.x behavior.

        Args:
            path: Path to the unified YAML file.
        """
        # PyYAML is a soft dep; import lazily so the core stays stdlib.
        from .yaml_evaluator import _load_yaml  # local to avoid cycle

        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        bundle = _load_yaml(text, source=path)
        return cls._from_bundle(bundle, source=path)

    @classmethod
    def from_text(cls, text: str, *, source: str = "<inline>") -> "Policy":
        """Construct from a YAML string. Used by tests and the CLI."""
        from .yaml_evaluator import _load_yaml

        bundle = _load_yaml(text, source=source)
        return cls._from_bundle(bundle, source=source)

    @classmethod
    def _from_bundle(cls, bundle: Any, *, source: str) -> "Policy":
        from .evaluator import PolicyParseError
        from .yaml_evaluator import NativeYamlEvaluator
        # Local import to avoid the retrieval ↔ tool-call cycle at module
        # load time. The tool-call evaluator subpackage imports from
        # provenex.policy.evaluator; this module being imported eagerly
        # from there would close the loop.
        from ..tool_call.evaluator import ToolCallPolicyEvaluator
        from ..tool_call.yaml_evaluator import NativeYamlToolCallEvaluator

        if not isinstance(bundle, dict):
            raise PolicyParseError(
                f"{source}: top-level must be a mapping, got {type(bundle).__name__}"
            )
        extras = set(bundle) - _UNIFIED_YAML_TOP_KEYS
        if extras:
            raise PolicyParseError(
                f"{source}: unknown top-level keys {sorted(extras)}. "
                f"Allowed: {sorted(_UNIFIED_YAML_TOP_KEYS)}"
            )
        version = bundle.get("version", 1)
        if version != 1:
            raise PolicyParseError(
                f"{source}: 'version' must be 1 (got {version!r})"
            )

        verification_block = bundle.get("verification")
        verification = _parse_verification(verification_block, source=source)

        access_control_block = bundle.get("access_control")
        access_control: Optional[PolicyEvaluator] = None
        if access_control_block is not None:
            access_control = NativeYamlEvaluator.from_unified_bundle(
                bundle, source=source
            )

        tool_call_control_block = bundle.get("tool_call_control")
        tool_call_control: Optional[ToolCallPolicyEvaluator] = None
        if tool_call_control_block is not None:
            tool_call_control = NativeYamlToolCallEvaluator.from_unified_bundle(
                bundle, source=source
            )

        availability_block = bundle.get("availability")
        availability = _parse_availability(availability_block, source=source)

        return cls(
            verification=verification,
            access_control=access_control,
            tool_call_control=tool_call_control,
            availability=availability,
        )


def _parse_verification(
    block: Any,
    *,
    source: str,
) -> VerificationPolicy:
    """Parse the ``verification:`` subsection into a :class:`VerificationPolicy`.

    Missing keys fall back to dataclass defaults. Unknown keys raise so
    a typo (``block_unauthroized`` ...) does not silently use defaults.
    """
    from .evaluator import PolicyParseError

    if block is None:
        return VerificationPolicy()
    if not isinstance(block, dict):
        raise PolicyParseError(
            f"{source}: 'verification' must be a mapping, got "
            f"{type(block).__name__}"
        )
    allowed = {
        "block_stale",
        "block_unauthorized",
        "block_unverified",
        "block_tampered",
        "flag_stale",
        "flag_unauthorized",
        "flag_unverified",
        "flag_tampered",
    }
    extras = set(block) - allowed
    if extras:
        raise PolicyParseError(
            f"{source}: verification has unknown keys {sorted(extras)}. "
            f"Allowed: {sorted(allowed)}"
        )
    for k, v in block.items():
        if not isinstance(v, bool):
            raise PolicyParseError(
                f"{source}: verification['{k}'] must be a boolean, got "
                f"{type(v).__name__}"
            )
    defaults = VerificationPolicy()
    return VerificationPolicy(
        block_stale=block.get("block_stale", defaults.block_stale),
        block_unauthorized=block.get("block_unauthorized", defaults.block_unauthorized),
        block_unverified=block.get("block_unverified", defaults.block_unverified),
        block_tampered=block.get("block_tampered", defaults.block_tampered),
        flag_stale=block.get("flag_stale", defaults.flag_stale),
        flag_unauthorized=block.get("flag_unauthorized", defaults.flag_unauthorized),
        flag_unverified=block.get("flag_unverified", defaults.flag_unverified),
        flag_tampered=block.get("flag_tampered", defaults.flag_tampered),
    )


def _parse_availability(
    block: Any,
    *,
    source: str,
) -> IndexAvailabilityPolicy:
    """Parse the ``availability:`` subsection into an :class:`IndexAvailabilityPolicy`.

    Missing keys fall back to dataclass defaults. Unknown keys raise so
    a typo (``on_index_errors`` ...) does not silently use defaults.
    """
    from .evaluator import PolicyParseError

    if block is None:
        return IndexAvailabilityPolicy()
    if not isinstance(block, dict):
        raise PolicyParseError(
            f"{source}: 'availability' must be a mapping, got "
            f"{type(block).__name__}"
        )
    allowed = {
        "on_index_error",
        "timeout_seconds",
        "breaker_threshold",
        "breaker_window_seconds",
        "breaker_cooldown_seconds",
    }
    extras = set(block) - allowed
    if extras:
        raise PolicyParseError(
            f"{source}: availability has unknown keys {sorted(extras)}. "
            f"Allowed: {sorted(allowed)}"
        )
    defaults = IndexAvailabilityPolicy()
    try:
        return IndexAvailabilityPolicy(
            on_index_error=block.get("on_index_error", defaults.on_index_error),
            timeout_seconds=block.get("timeout_seconds", defaults.timeout_seconds),
            breaker_threshold=block.get(
                "breaker_threshold", defaults.breaker_threshold
            ),
            breaker_window_seconds=block.get(
                "breaker_window_seconds", defaults.breaker_window_seconds
            ),
            breaker_cooldown_seconds=block.get(
                "breaker_cooldown_seconds", defaults.breaker_cooldown_seconds
            ),
        )
    except ValueError as exc:
        raise PolicyParseError(f"{source}: {exc}") from exc


def coerce_policy(value: Any) -> "Policy":
    """Normalise a caller-supplied policy argument into a :class:`Policy`.

    Accepts:

    * A :class:`Policy` (returned as-is).
    * A :class:`VerificationPolicy` (wrapped in a Policy with no access control).
    * ``None`` (returns default Policy).

    Used by the framework integrations so their existing ``policy=`` kwargs
    keep working with old VerificationPolicy callers while the unified
    Policy lands as the canonical type.
    """
    if value is None:
        return Policy()
    if isinstance(value, Policy):
        return value
    if isinstance(value, VerificationPolicy):
        return Policy(verification=value)
    raise TypeError(
        f"policy must be Policy, VerificationPolicy, or None; got "
        f"{type(value).__name__}"
    )


def build_access_control_metadata(
    evaluator: PolicyEvaluator,
    decisions: list,
) -> Dict[str, Any]:
    """Assemble the ``policy.access_control`` payload for a receipt.

    Centralised so the wiring in :mod:`provenex.core.verify` and any
    future framework wrappers all emit the same shape.
    """
    return {
        "evaluator": evaluator.evaluator_name,
        "policy_id": evaluator.policy_id,
        "policy_version_hash": evaluator.policy_version_hash,
        # this lights this up alongside the transparency-log
        # integration for policy bundles. Always False in v0.4.
        "policy_in_transparency_log": False,
        "decisions": list(decisions),
    }
