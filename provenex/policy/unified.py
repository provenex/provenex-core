"""Unified :class:`Policy` wrapper.

Schema 2.0.0 unified the verification gate and the data-access gate under
a single top-level ``policy`` block on the receipt. The Python API
mirrors that shape: callers construct one :class:`Policy` carrying both
halves, and pass it to :func:`provenex.verify_chunks`.

Two halves:

* ``verification`` — :class:`VerificationPolicy` controlling which of the
  five outcomes (VERIFIED / STALE / UNAUTHORIZED / UNVERIFIED / TAMPERED)
  block a chunk before it reaches the next stage.
* ``access_control`` — an optional :class:`PolicyEvaluator` that runs
  declarative rules over chunk metadata and the request context. The
  native YAML evaluator is the reference backend. The Rego adapter and
  the OPA service adapter are commercial.

A chunk reaches the LLM only if BOTH halves allow it. The verification
half is always present (with sensible defaults if the caller doesn't
override). The access-control half is optional — for early-stage
deployments that want the verification gate alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .evaluator import PolicyEvaluator
from .policy import VerificationPolicy

# Reserved top-level YAML keys for the unified config file. Anything else
# at the top level raises a parse error — the convention is "load loud,
# fail loud" so typos can't silently allow.
_UNIFIED_YAML_TOP_KEYS = frozenset(
    {"version", "policy_id", "description", "verification", "access_control"}
)


@dataclass(frozen=True)
class Policy:
    """The single policy object the caller passes to ``verify_chunks``.

    Attributes:
        verification: The five-outcome verification gate config. Defaults
            to :class:`VerificationPolicy` defaults (block UNAUTHORIZED
            and TAMPERED; flag everything else).
        access_control: Optional :class:`PolicyEvaluator` running
            declarative access-control rules. ``None`` means no access
            policy is in effect — only the verification gate applies, and
            the receipt's ``policy.access_control`` block is omitted.
    """

    verification: VerificationPolicy = field(default_factory=VerificationPolicy)
    access_control: Optional[PolicyEvaluator] = None

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
        return cls(verification=verification, access_control=access_control)


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
        # Phase 2 lights this up alongside the transparency-log
        # integration for policy bundles. Always False in v0.4.
        "policy_in_transparency_log": False,
        "decisions": list(decisions),
    }
