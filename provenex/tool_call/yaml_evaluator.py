"""Native YAML tool-call admission evaluator (schema 2.2.0).

The tool-call admission analog of :class:`provenex.policy.yaml_evaluator.NativeYamlEvaluator`.
Same DSL grammar (``when`` / ``require`` / ``on_violation``), same
operators (extended with ``matches_pattern`` / ``not_matches_pattern`` /
``length_at_most`` in schema 2.2.0), but rules see ``tool.*`` and
``request.*`` instead of ``chunk.*`` and ``request.*``.

Loading paths:

    * :meth:`from_text` / :meth:`from_path` — read a bundle directly
      (legacy layout: ``rules`` at the top level).
    * :meth:`from_unified_bundle` — pulled from a unified policy file's
      ``tool_call_control:`` subsection. This is the path
      :meth:`provenex.Policy.from_yaml` takes for the common case where
      both halves are authored in one file.

``policy_version_hash`` covers the tool-call subset only — adding or
changing ``verification:`` or ``access_control:`` in the same unified
file does not change the tool-call hash. The two halves version
independently, the same way the retrieval-side access-control hash does.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..policy.evaluator import (
    DECISION_ALLOW,
    DECISION_DENY,
    EVALUATOR_NATIVE_YAML,
    PolicyDecision,
    PolicyParseError,
    RequestContext,
    UnsupportedPolicyFeature,
    compute_inputs_hash,
    compute_policy_version_hash,
)
from ..policy.yaml_evaluator import (
    _MISSING,
    _TOOL_CALL_DOMAIN_ROOTS,
    _check_constraint,
    _load_yaml,
    _resolve_path,
    _validate_defaults,
    _validate_rule,
    _when_matches,
)
from .context import ToolCallContext
from .evaluator import ToolCallPolicyEvaluator, build_tool_call_inputs


# --------------------------------------------------------------------------- #
# Evaluator                                                                   #
# --------------------------------------------------------------------------- #


class NativeYamlToolCallEvaluator(ToolCallPolicyEvaluator):
    """Reference :class:`ToolCallPolicyEvaluator` backed by the native DSL.

    Construct via :meth:`from_path` (file on disk), :meth:`from_text`
    (in-memory string for tests), or :meth:`from_unified_bundle` (a
    pre-parsed unified-config dict, used by :meth:`provenex.Policy.from_yaml`
    to avoid re-parsing).

    The constructor validates the bundle eagerly: a malformed policy
    raises at load time, not at evaluation time. A rule in a tool-call
    bundle that references ``chunk.*`` is rejected at parse time so
    operators cannot mix domains by accident.

    Thread-safety: immutable after construction; safe to share across
    threads.
    """

    def __init__(self, bundle: Dict[str, Any], *, source: str) -> None:
        self._source = source
        self._bundle = bundle
        self._rules: List[Dict[str, Any]] = self._validate_bundle(bundle, source)
        self._defaults: Dict[str, str] = _validate_defaults(
            bundle.get("defaults"), source=source
        )
        self._policy_id: str = self._read_policy_id(bundle, source)
        self._policy_version_hash: str = compute_policy_version_hash(bundle)

    @staticmethod
    def _validate_bundle(bundle: Any, source: str) -> List[Dict[str, Any]]:
        if not isinstance(bundle, dict):
            raise PolicyParseError(
                f"{source}: top-level must be a mapping, got {type(bundle).__name__}"
            )
        version = bundle.get("version")
        if version != 1:
            raise PolicyParseError(
                f"{source}: 'version' must be 1 (got {version!r})"
            )
        rules = bundle.get("rules")
        if not isinstance(rules, list):
            raise PolicyParseError(
                f"{source}: 'rules' must be a list (got {type(rules).__name__})"
            )
        return [
            _validate_rule(
                r, idx=i, source=source, allowed_roots=_TOOL_CALL_DOMAIN_ROOTS
            )
            for i, r in enumerate(rules)
        ]

    @staticmethod
    def _read_policy_id(bundle: Dict[str, Any], source: str) -> str:
        pid = bundle.get("policy_id")
        if not isinstance(pid, str) or not pid:
            raise PolicyParseError(
                f"{source}: top-level 'policy_id' is required and must be a "
                f"non-empty string"
            )
        return pid

    # ----- constructors ----- #

    @classmethod
    def from_text(
        cls,
        text: str,
        *,
        source: str = "<inline>",
    ) -> "NativeYamlToolCallEvaluator":
        """Construct from a YAML string. ``source`` appears in error messages.

        Accepts:

        * A unified Provenex policy file with ``tool_call_control:`` at
          the top level (the standard layout used in production).
        * A legacy tool-call-only file with ``rules:`` at the top.

        The bundle is normalised internally; ``policy_version_hash``
        covers only the tool-call subset.
        """
        bundle = _load_yaml(text, source=source)
        return cls._construct_from_bundle(bundle, source=source)

    @classmethod
    def from_path(cls, path: str) -> "NativeYamlToolCallEvaluator":
        """Construct from a file on disk."""
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        return cls.from_text(text, source=path)

    @classmethod
    def from_unified_bundle(
        cls,
        bundle: Dict[str, Any],
        *,
        source: str,
    ) -> "NativeYamlToolCallEvaluator":
        """Construct from an already-parsed unified-config dict.

        Used by :meth:`provenex.Policy._from_bundle` to avoid re-parsing
        the YAML once for the policy and again for the evaluator.
        """
        return cls._construct_from_bundle(bundle, source=source)

    @classmethod
    def _construct_from_bundle(
        cls,
        bundle: Any,
        *,
        source: str,
    ) -> "NativeYamlToolCallEvaluator":
        """Detect unified vs legacy layout and construct the evaluator.

        Unified layout: top-level ``tool_call_control:`` carries
        rules/defaults; the outer dict carries ``policy_id``. Legacy
        layout: rules and defaults live at the top level alongside
        ``policy_id``.
        """
        if not isinstance(bundle, dict):
            raise PolicyParseError(
                f"{source}: top-level must be a mapping, got {type(bundle).__name__}"
            )

        if "tool_call_control" in bundle:
            tcc = bundle["tool_call_control"]
            if not isinstance(tcc, dict):
                raise PolicyParseError(
                    f"{source}: 'tool_call_control' must be a mapping, got "
                    f"{type(tcc).__name__}"
                )
            normalized: Dict[str, Any] = {
                "version": bundle.get("version", 1),
                "policy_id": bundle.get("policy_id") or tcc.get("policy_id"),
                "rules": tcc.get("rules", []),
            }
            if "defaults" in tcc:
                normalized["defaults"] = tcc["defaults"]
            if "description" in bundle:
                normalized["description"] = bundle["description"]
            return cls(normalized, source=source)

        # Legacy layout: rules at top level.
        return cls(bundle, source=source)

    # ----- protocol surface ----- #

    @property
    def evaluator_name(self) -> str:
        return EVALUATOR_NATIVE_YAML

    @property
    def policy_id(self) -> str:
        return self._policy_id

    @property
    def policy_version_hash(self) -> str:
        return self._policy_version_hash

    @property
    def source(self) -> str:
        """Human-readable origin (file path or ``"<inline>"``)."""
        return self._source

    @property
    def bundle(self) -> Dict[str, Any]:
        """The parsed policy bundle (a copy). Useful for CLI hash printing."""
        return dict(self._bundle)

    def evaluate(
        self,
        tool: ToolCallContext,
        request: RequestContext,
    ) -> PolicyDecision:
        inputs = build_tool_call_inputs(tool, request)
        inputs_hash = compute_inputs_hash(inputs)

        rules_fired: List[str] = []
        for rule in self._rules:
            if not _when_matches(rule["when"], tool=tool, request=request):
                continue
            rules_fired.append(rule["name"])
            # First failure denies.
            for path, constraint in rule["require"].items():
                actual = _resolve_path(path, tool=tool, request=request)
                ok, _why = _check_constraint(
                    path,
                    constraint,
                    actual,
                    request=request,
                    unknown_metadata_default=self._defaults["unknown_metadata"],
                )
                if not ok:
                    return PolicyDecision(
                        decision=DECISION_DENY,
                        rules_fired=rules_fired,
                        inputs_hash=inputs_hash,
                        inputs=inputs,
                    )
        return PolicyDecision(
            decision=DECISION_ALLOW,
            rules_fired=rules_fired,
            inputs_hash=inputs_hash,
            inputs=inputs,
        )


# --------------------------------------------------------------------------- #
# CLI helpers                                                                 #
# --------------------------------------------------------------------------- #


def validate_tool_call_policy_file(path: str) -> Tuple[bool, Optional[str]]:
    """Validate a tool-call policy file at ``path``.

    Mirror of :func:`provenex.policy.yaml_evaluator.validate_policy_file`
    for the tool-call domain. Used by the ``provenex policy validate``
    subcommand when a file's top level carries ``tool_call_control:``
    rather than (or alongside) ``access_control:``.
    """
    try:
        NativeYamlToolCallEvaluator.from_path(path)
    except (PolicyParseError, UnsupportedPolicyFeature) as exc:
        return False, str(exc)
    except FileNotFoundError as exc:
        return False, f"file not found: {exc.filename}"
    return True, None
