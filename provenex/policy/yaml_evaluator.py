"""Native YAML data-access policy evaluator.

This is the reference implementation of :class:`PolicyEvaluator`. It loads
a constrained YAML DSL (see :mod:`docs/policy.md`) and evaluates each
``(chunk, request)`` pair against the rules.

The DSL is intentionally small. The DSL supports:

    * ``when`` — flat key/value map. Rule applies iff every condition
      matches via direct equality.
    * ``require`` — flat key/value map. Constraints. Operators:
      direct equality, ``in``, ``not_in``, ``not_older_than``.
    * ``on_violation: deny`` (the only value supported).
    * ``defaults.unknown_metadata`` and ``defaults.policy_version_mismatch``
      — both default to ``deny``.

Anything else (``any_of``, ``all_of``, negation, nested rules, custom
functions, external lookups) raises :class:`UnsupportedPolicyFeature`.
The error names the feature so the operator knows what to remove.
This matters: a silent "policy file typo opens a gate" is the worst
possible failure mode.

PyYAML is imported lazily so the core remains pure-stdlib installable.
Operators who use the YAML DSL install the extra:

    pip install provenex-core[policy]
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from .evaluator import (
    DECISION_ALLOW,
    DECISION_DENY,
    EVALUATOR_NATIVE_YAML,
    ChunkContext,
    PolicyDecision,
    PolicyEvaluator,
    PolicyParseError,
    RequestContext,
    UnsupportedPolicyFeature,
    _build_inputs,
    compute_inputs_hash,
    compute_policy_version_hash,
)

# Operator names recognised inside ``require`` clauses. Anything else in
# an operator-style mapping (a dict value under a require key) is rejected
# at parse time so a typo cannot silently allow.
#
# (schema 2.2.0) adds ``matches_pattern`` / ``not_matches_pattern``
# (POSIX ``fnmatch`` globs; deliberately not regex — globs are auditable,
# regexes are a footgun) and ``length_at_most`` (integer cap on string-
# valued paths; cheapest mitigation against parameter-size injection).
# These work on any string-valued path and are domain-agnostic.
_KNOWN_REQUIRE_OPERATORS = frozenset(
    {
        "in",
        "not_in",
        "not_older_than",
        "matches_pattern",
        "not_matches_pattern",
        "length_at_most",
    }
)

# Hard ceiling on the input length to ``matches_pattern`` /
# ``not_matches_pattern``. fnmatch.fnmatchcase is linear in the typical
# case but pathological globs paired with very large inputs can still
# burn cycles; this cap bounds the per-decision cost regardless of how
# the policy is authored. 64 KiB is comfortably above any realistic
# tool-parameter / metadata value while well below the size at which
# pattern evaluation becomes a per-request DoS vector. Operators who
# need to match larger strings should declare an explicit
# ``length_at_most`` companion rule (which sees this cap, not the
# truncated input).
_MAX_PATTERN_INPUT_LEN = 65536

# Path roots a rule is allowed to reference, by domain. The
# ``access_control`` rules see chunks and the request context; tool-call
# ``tool_call_control`` rules see tool calls and the request context.
# Cross-domain references fail at parse time so an operator cannot
# accidentally write a chunk rule that references ``tool.parameters``
# (or vice versa) and have it silently evaluate as missing.
_CHUNK_DOMAIN_ROOTS: FrozenSet[str] = frozenset({"chunk", "request"})
_TOOL_CALL_DOMAIN_ROOTS: FrozenSet[str] = frozenset({"tool", "request"})

# Reserved-but-unimplemented top-level keys and rule-level keys. Listing
# them explicitly lets us raise a precise UnsupportedPolicyFeature rather
# than the generic "unknown key" parse error.
_RESERVED_RULE_KEYS = frozenset({"any_of", "all_of", "not", "nested"})

# Duration suffixes for ``not_older_than``. Brief specifies d/h/m; we add
# seconds for completeness without inviting scope creep. Anything else
# raises a parse error.
_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")
_DURATION_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


# --------------------------------------------------------------------------- #
# Parsing                                                                     #
# --------------------------------------------------------------------------- #


def _load_yaml(text: str, *, source: str) -> Any:
    """Lazy-import PyYAML and parse a string, mapping errors to PolicyParseError.

    Args:
        text: The YAML source.
        source: A human-readable identifier (file path or ``"<inline>"``)
            included in error messages.
    """
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        raise PolicyParseError(
            "The native YAML evaluator requires PyYAML. "
            "Install it with: pip install provenex-core[policy]"
        ) from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        # PyYAML errors carry a ``problem_mark`` with line/column. Surface
        # it so the operator can navigate to the typo.
        mark = getattr(exc, "problem_mark", None)
        loc = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise PolicyParseError(
            f"YAML parse error in {source}{loc}: {exc}"
        ) from exc


def _parse_duration(value: Any, *, where: str) -> int:
    """Parse a duration string like ``"90d"`` into seconds."""
    if not isinstance(value, str):
        raise PolicyParseError(
            f"{where}: expected a duration string (e.g. '90d', '24h', '30m'), "
            f"got {type(value).__name__}"
        )
    m = _DURATION_RE.match(value)
    if not m:
        raise PolicyParseError(
            f"{where}: invalid duration {value!r}; "
            f"use <int><unit> with unit one of s/m/h/d"
        )
    qty = int(m.group(1))
    unit = m.group(2)
    return qty * _DURATION_UNIT_SECONDS[unit]


def _parse_iso8601(value: str, *, where: str) -> int:
    """Parse an ISO-8601 timestamp into a UTC epoch second count."""
    from datetime import datetime, timezone

    # The fingerprinter/index emits timestamps like "2026-04-01T09:00:00.123Z".
    # datetime.fromisoformat in 3.11+ accepts the trailing 'Z'; earlier
    # versions need a swap.
    s = value
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as exc:
        raise PolicyParseError(f"{where}: invalid ISO-8601 timestamp {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _check_no_reserved_keys(
    d: Dict[str, Any],
    *,
    where: str,
) -> None:
    """Raise UnsupportedPolicyFeature if ``d`` uses a reserved key."""
    for k in d:
        if k in _RESERVED_RULE_KEYS:
            raise UnsupportedPolicyFeature(
                f"{where}: '{k}' is reserved for a future release. "
                f"The DSL supports flat when/require maps only."
            )


def _validate_path_root(
    path: str,
    *,
    allowed_roots: FrozenSet[str],
    where: str,
) -> None:
    """Reject a path whose root is not in this rule's domain.

    Schema 2.2.0 introduced two parallel rule domains (``access_control`` for
    chunks, ``tool_call_control`` for tool calls). Each domain allows a
    distinct set of path roots. Cross-domain references fail here at
    parse time rather than evaluating as missing at runtime — silent
    evaluate-as-missing would be a "policy file typo opens a gate"
    failure mode, exactly what the strict-load discipline exists to
    prevent.
    """
    if not isinstance(path, str) or "." not in path:
        # Will fail elsewhere on shape; nothing to validate here.
        return
    root = path.split(".", 1)[0]
    if root not in allowed_roots:
        raise PolicyParseError(
            f"{where}: path {path!r} uses root {root!r} which is not "
            f"allowed in this rule's domain. Allowed roots: "
            f"{sorted(allowed_roots)}"
        )


def _validate_rule(
    rule: Any,
    *,
    idx: int,
    source: str,
    allowed_roots: FrozenSet[str] = _CHUNK_DOMAIN_ROOTS,
) -> Dict[str, Any]:
    """Validate one rule dict and return it normalized.

    Catches the worst case (silent allow) by being strict about unknown
    keys and unknown operators. A typo is a parse error, not a permissive
    default.

    ``allowed_roots`` controls which path roots the rule may reference.
    Defaults to the chunk domain (``{"chunk", "request"}``) so
    existing call sites behave identically. tool-call admission callers pass the
    tool-call domain.
    """
    if not isinstance(rule, dict):
        raise PolicyParseError(
            f"{source}: rules[{idx}] must be a mapping, got {type(rule).__name__}"
        )
    name = rule.get("name")
    if not isinstance(name, str) or not name:
        raise PolicyParseError(
            f"{source}: rules[{idx}] is missing a non-empty 'name'"
        )
    _check_no_reserved_keys(rule, where=f"{source}: rule '{name}'")

    allowed_keys = {"name", "when", "require", "on_violation"}
    extras = set(rule) - allowed_keys
    if extras:
        raise PolicyParseError(
            f"{source}: rule '{name}' has unknown keys: {sorted(extras)}. "
            f"Allowed keys: {sorted(allowed_keys)}"
        )

    when = rule.get("when") or {}
    if not isinstance(when, dict):
        raise PolicyParseError(
            f"{source}: rule '{name}': 'when' must be a mapping"
        )
    _check_no_reserved_keys(when, where=f"{source}: rule '{name}' when")
    for path, expected in when.items():
        _validate_path_root(
            path,
            allowed_roots=allowed_roots,
            where=f"{source}: rule '{name}' when",
        )
        # ``when`` accepts direct equality (scalar RHS) or ``{in: [...]}``
        # membership. Anything else — including the rich operators
        # allowed in ``require`` — is rejected at parse time so a typo
        # cannot silently turn a strict gate into an open one.
        if isinstance(expected, dict):
            unknown = set(expected) - {"in"}
            if unknown:
                raise PolicyParseError(
                    f"{source}: rule '{name}' when['{path}'] uses operator(s) "
                    f"{sorted(unknown)} not supported in 'when'. Only direct "
                    f"equality and 'in' are allowed here; move richer logic "
                    f"into 'require'."
                )
            if "in" in expected and not isinstance(expected["in"], list):
                raise PolicyParseError(
                    f"{source}: rule '{name}' when['{path}'].in must be a list"
                )

    require = rule.get("require") or {}
    if not isinstance(require, dict):
        raise PolicyParseError(
            f"{source}: rule '{name}': 'require' must be a mapping"
        )
    _check_no_reserved_keys(require, where=f"{source}: rule '{name}' require")
    # Validate operator-style require values eagerly: unknown operators,
    # bad duration strings, and wrong shapes (in/not_in not a list) should
    # all fail at load time, not silently allow at evaluation time.
    for path, constraint in require.items():
        _validate_path_root(
            path,
            allowed_roots=allowed_roots,
            where=f"{source}: rule '{name}' require",
        )
        if isinstance(constraint, dict):
            unknown_ops = set(constraint) - _KNOWN_REQUIRE_OPERATORS
            if unknown_ops:
                raise PolicyParseError(
                    f"{source}: rule '{name}' require['{path}'] uses unknown "
                    f"operator(s) {sorted(unknown_ops)}. "
                    f"Known operators: {sorted(_KNOWN_REQUIRE_OPERATORS)}"
                )
            if "in" in constraint and not isinstance(constraint["in"], list):
                raise PolicyParseError(
                    f"{source}: rule '{name}' require['{path}'].in must be a list"
                )
            if "not_in" in constraint and not isinstance(constraint["not_in"], list):
                raise PolicyParseError(
                    f"{source}: rule '{name}' require['{path}'].not_in must be a list"
                )
            if "not_older_than" in constraint:
                # Validates duration syntax; raises PolicyParseError on a typo.
                _parse_duration(
                    constraint["not_older_than"],
                    where=(
                        f"{source}: rule '{name}' "
                        f"require['{path}'].not_older_than"
                    ),
                )
            for op in ("matches_pattern", "not_matches_pattern"):
                if op in constraint and not isinstance(constraint[op], str):
                    raise PolicyParseError(
                        f"{source}: rule '{name}' require['{path}'].{op} "
                        f"must be a glob pattern string (e.g. '*.example.com')"
                    )
            if "length_at_most" in constraint:
                v = constraint["length_at_most"]
                if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                    raise PolicyParseError(
                        f"{source}: rule '{name}' "
                        f"require['{path}'].length_at_most must be a "
                        f"non-negative integer (got {v!r})"
                    )

    on_violation = rule.get("on_violation", "deny")
    if on_violation != "deny":
        raise PolicyParseError(
            f"{source}: rule '{name}': on_violation must be 'deny' "
            f"(got {on_violation!r})"
        )

    return {
        "name": name,
        "when": when,
        "require": require,
        "on_violation": on_violation,
    }


def _validate_defaults(defaults: Any, *, source: str) -> Dict[str, str]:
    """Validate the top-level ``defaults`` block and return it normalized."""
    if defaults is None:
        return {"unknown_metadata": "deny", "policy_version_mismatch": "deny"}
    if not isinstance(defaults, dict):
        raise PolicyParseError(
            f"{source}: 'defaults' must be a mapping, got {type(defaults).__name__}"
        )
    allowed_keys = {"unknown_metadata", "policy_version_mismatch"}
    extras = set(defaults) - allowed_keys
    if extras:
        raise PolicyParseError(
            f"{source}: defaults has unknown keys: {sorted(extras)}. "
            f"Allowed: {sorted(allowed_keys)}"
        )
    out: Dict[str, str] = {}
    for k in allowed_keys:
        v = defaults.get(k, "deny")
        if v not in ("allow", "deny"):
            raise PolicyParseError(
                f"{source}: defaults['{k}'] must be 'allow' or 'deny', got {v!r}"
            )
        out[k] = v
    return out


# --------------------------------------------------------------------------- #
# Path resolution and operator evaluation                                     #
# --------------------------------------------------------------------------- #

# Sentinel returned by _resolve_path when the path doesn't exist in the
# context. Distinct from ``None`` because ``None`` is a legitimate value
# (e.g. ``request.jurisdiction`` may be explicitly None).
_MISSING = object()


def _resolve_path(
    path: str,
    *,
    chunk: Optional[ChunkContext] = None,
    request: RequestContext,
    tool: Optional[Any] = None,
) -> Any:
    """Walk a dotted path against the (chunk | tool, request) context.

    Path roots recognised:

        * ``chunk.*`` — attributes of :class:`ChunkContext`. Within
          ``chunk.metadata`` further dotted segments index into the
          metadata dict.
        * ``request.*`` — attributes of :class:`RequestContext`. Within
          ``request.caller`` further segments index into the caller dict.
          Shared.
        * ``tool.*`` — attributes of
          :class:`provenex.tool_call.ToolCallContext`. Within
          ``tool.parameters`` further dotted segments index into the
          parameter dict.

    Exactly one of ``chunk`` or ``tool`` is supplied per evaluation
    (retrieval callers pass ``chunk``, tool-call admission callers pass ``tool``). A
    rule that references a path root absent from the supplied contexts
    resolves to :data:`_MISSING` — but parse-time validation
    (:func:`_validate_path_root`) ensures that cannot happen for a
    well-formed bundle.

    Returns :data:`_MISSING` if any segment doesn't exist. Note that an
    explicit ``None`` in the source is returned as ``None``, not
    ``_MISSING`` — these are different things.
    """
    parts = path.split(".")
    if not parts:
        return _MISSING
    root = parts[0]
    if root == "chunk":
        if chunk is None:
            return _MISSING
        current: Any = chunk
        for seg in parts[1:]:
            if isinstance(current, dict):
                if seg not in current:
                    return _MISSING
                current = current[seg]
            else:
                # Dataclass field — getattr returns _MISSING sentinel for
                # absent fields.
                current = getattr(current, seg, _MISSING)
                if current is _MISSING:
                    return _MISSING
        return current
    if root == "tool":
        if tool is None:
            return _MISSING
        current = tool
        for seg in parts[1:]:
            if isinstance(current, dict):
                if seg not in current:
                    return _MISSING
                current = current[seg]
            else:
                current = getattr(current, seg, _MISSING)
                if current is _MISSING:
                    return _MISSING
        return current
    if root == "request":
        current = request
        for seg in parts[1:]:
            if isinstance(current, dict):
                if seg not in current:
                    return _MISSING
                current = current[seg]
            else:
                current = getattr(current, seg, _MISSING)
                if current is _MISSING:
                    return _MISSING
        return current
    raise PolicyParseError(
        f"unknown path root {root!r} in {path!r}; "
        f"expected 'chunk', 'tool', or 'request'"
    )


def _when_matches(
    when: Dict[str, Any],
    *,
    chunk: Optional[ChunkContext] = None,
    request: RequestContext,
    tool: Optional[Any] = None,
) -> bool:
    """Return True iff every key in ``when`` matches its expected value.

    Each ``when`` entry is one of:

        * **Direct equality** (scalar RHS) — the path resolves to a value
          equal to the RHS. The original form.
        * **`in:` membership** (``{in: [a, b, c]}`` RHS) — the path
          resolves to a value in the list. Added in schema 2.2.0 to keep
          CRUD-style tool-call rules from needing three near-identical
          duplicates ("if the operation is one of create_issue /
          update_issue / delete_issue, require ...").

    No other operators are supported in ``when``. ``when`` is meant to be
    a quick "does this rule apply" filter; richer logic belongs in
    ``require``.

    A missing path means "no match" — rule scope doesn't apply. This is
    deliberately distinct from a ``require`` clause referencing a missing
    path, which is governed by ``defaults.unknown_metadata``.
    """
    for path, expected in when.items():
        actual = _resolve_path(path, chunk=chunk, request=request, tool=tool)
        if actual is _MISSING:
            return False
        if isinstance(expected, dict):
            # The only supported operator in a `when` clause is `in:`.
            # Validated at parse time; anything else is an error.
            if "in" in expected:
                if actual not in expected["in"]:
                    return False
                continue
            # Should be unreachable thanks to parse-time validation, but
            # defensive against future extensions adding operators that
            # forget to update parse-side checks.
            return False
        if actual != expected:
            return False
    return True


def _check_constraint(
    path: str,
    constraint: Any,
    actual: Any,
    *,
    request: RequestContext,
    unknown_metadata_default: str,
) -> Tuple[bool, str]:
    """Check one constraint against ``actual``.

    Returns ``(ok, why)``. ``why`` is a short human-readable explanation
    used in error messages (rules_fired carries names, not whys; this is
    for future verbose-mode CLI output).
    """
    if actual is _MISSING:
        # Missing metadata path. Apply the operator-default policy.
        if unknown_metadata_default == "allow":
            return True, f"{path}: missing metadata; default allow"
        return False, f"{path}: missing metadata; default deny"

    # Scalar equality.
    if not isinstance(constraint, dict):
        return (actual == constraint), f"{path}: equality"

    # Operator-style constraint. We have already validated that only
    # known operators appear here in _validate_rule.
    if "in" in constraint:
        allowed = constraint["in"]
        if not isinstance(allowed, list):
            return False, f"{path}: 'in' requires a list"
        return (actual in allowed), f"{path}: in {allowed}"
    if "not_in" in constraint:
        denied = constraint["not_in"]
        if not isinstance(denied, list):
            return False, f"{path}: 'not_in' requires a list"
        return (actual not in denied), f"{path}: not_in {denied}"
    if "not_older_than" in constraint:
        if not isinstance(actual, str):
            return False, (
                f"{path}: 'not_older_than' requires an ISO-8601 string value, "
                f"got {type(actual).__name__}"
            )
        max_age_s = _parse_duration(
            constraint["not_older_than"],
            where=f"require['{path}'].not_older_than",
        )
        try:
            actual_epoch = _parse_iso8601(
                actual, where=f"chunk value at '{path}'"
            )
            now_epoch = _parse_iso8601(
                request.timestamp, where="request.timestamp"
            )
        except PolicyParseError:
            # Malformed timestamps at evaluation time are a deny — better
            # than crashing the retriever.
            return False, f"{path}: invalid timestamp"
        age_s = now_epoch - actual_epoch
        return (age_s <= max_age_s), f"{path}: age={age_s}s <= {max_age_s}s"
    if "matches_pattern" in constraint:
        pattern = constraint["matches_pattern"]
        if not isinstance(actual, str):
            return False, (
                f"{path}: 'matches_pattern' requires a string value, "
                f"got {type(actual).__name__}"
            )
        if len(actual) > _MAX_PATTERN_INPUT_LEN:
            # Fail-closed: oversized inputs cannot satisfy a require/match,
            # so the rule fires and denies. Prevents O(N×M) work from an
            # unbounded upstream value paired with a glob containing many
            # ``*`` segments. Operators who legitimately need to match
            # larger strings should add a companion ``length_at_most``
            # rule or raise this cap.
            return False, (
                f"{path}: matches_pattern input rejected "
                f"(len={len(actual)} > {_MAX_PATTERN_INPUT_LEN})"
            )
        return fnmatch.fnmatchcase(actual, pattern), (
            f"{path}: matches_pattern {pattern!r}"
        )
    if "not_matches_pattern" in constraint:
        pattern = constraint["not_matches_pattern"]
        if not isinstance(actual, str):
            return False, (
                f"{path}: 'not_matches_pattern' requires a string value, "
                f"got {type(actual).__name__}"
            )
        if len(actual) > _MAX_PATTERN_INPUT_LEN:
            # Same fail-closed semantics as ``matches_pattern`` above:
            # the require fails, the rule fires.
            return False, (
                f"{path}: not_matches_pattern input rejected "
                f"(len={len(actual)} > {_MAX_PATTERN_INPUT_LEN})"
            )
        return (not fnmatch.fnmatchcase(actual, pattern)), (
            f"{path}: not_matches_pattern {pattern!r}"
        )
    if "length_at_most" in constraint:
        cap = constraint["length_at_most"]
        if not isinstance(actual, str):
            return False, (
                f"{path}: 'length_at_most' requires a string value, "
                f"got {type(actual).__name__}"
            )
        return (len(actual) <= cap), f"{path}: len={len(actual)} <= {cap}"
    return False, f"{path}: unrecognised constraint shape"


# --------------------------------------------------------------------------- #
# Evaluator                                                                   #
# --------------------------------------------------------------------------- #


class NativeYamlEvaluator(PolicyEvaluator):
    """Reference :class:`PolicyEvaluator` backed by the native YAML DSL.

    Construct via :meth:`from_path` (file on disk) or :meth:`from_text`
    (in-memory string, useful for tests). The constructor validates the
    bundle eagerly: a malformed policy raises at load time, not at
    evaluation time.

    Thread-safety: the evaluator is immutable after construction and safe
    to share across threads.
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
        return [_validate_rule(r, idx=i, source=source) for i, r in enumerate(rules)]

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
    def from_text(cls, text: str, *, source: str = "<inline>") -> "NativeYamlEvaluator":
        """Construct from a YAML string. ``source`` appears in error messages.

        Accepts either:

        * A unified Provenex policy file with ``access_control:`` at the
          top level (the v0.4 layout shared with :class:`Policy.from_yaml`).
        * A legacy access-control-only file with ``rules:`` at the top.

        Either way the bundle is normalised internally; the
        ``policy_version_hash`` covers only the access-control subset, so
        adding or changing the ``verification:`` section of a unified
        file does NOT change the access-control hash. The two halves
        version independently.
        """
        bundle = _load_yaml(text, source=source)
        return cls._construct_from_bundle(bundle, source=source)

    @classmethod
    def from_path(cls, path: str) -> "NativeYamlEvaluator":
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
    ) -> "NativeYamlEvaluator":
        """Construct from an already-parsed unified-config dict.

        Used by :meth:`Policy._from_bundle` to avoid re-parsing the YAML
        once for the policy and again for the evaluator.
        """
        return cls._construct_from_bundle(bundle, source=source)

    @classmethod
    def _construct_from_bundle(
        cls,
        bundle: Any,
        *,
        source: str,
    ) -> "NativeYamlEvaluator":
        """Detect unified vs legacy layout and construct the evaluator.

        Unified layout: top-level ``access_control:`` carries rules/defaults
        and the outer dict carries ``policy_id``. Legacy layout: rules and
        defaults live at the top level alongside ``policy_id``.
        """
        from .evaluator import PolicyParseError

        if not isinstance(bundle, dict):
            raise PolicyParseError(
                f"{source}: top-level must be a mapping, got {type(bundle).__name__}"
            )

        if "access_control" in bundle:
            ac = bundle["access_control"]
            if not isinstance(ac, dict):
                raise PolicyParseError(
                    f"{source}: 'access_control' must be a mapping, got "
                    f"{type(ac).__name__}"
                )
            # Synthesize the legacy bundle shape the existing validator
            # expects. policy_id may be at the outer level (unified) or
            # nested (legacy-within-unified).
            normalized: Dict[str, Any] = {
                "version": bundle.get("version", 1),
                "policy_id": bundle.get("policy_id") or ac.get("policy_id"),
                "rules": ac.get("rules", []),
            }
            if "defaults" in ac:
                normalized["defaults"] = ac["defaults"]
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
        chunk: ChunkContext,
        request: RequestContext,
    ) -> PolicyDecision:
        inputs = _build_inputs(chunk, request)
        inputs_hash = compute_inputs_hash(inputs)

        rules_fired: List[str] = []
        for rule in self._rules:
            if not _when_matches(rule["when"], chunk=chunk, request=request):
                continue
            rules_fired.append(rule["name"])
            # Evaluate every require constraint. First failure denies.
            for path, constraint in rule["require"].items():
                actual = _resolve_path(path, chunk=chunk, request=request)
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


def validate_policy_file(path: str) -> Tuple[bool, Optional[str]]:
    """Validate a policy file at ``path``. Returns ``(ok, error_message)``.

    Used by the ``provenex policy validate`` subcommand. Returning a tuple
    rather than raising lets the CLI format the error without unwrapping
    an exception.

    Accepts:

        * Unified-layout files (schema 2.0.0+): top-level
          ``verification:`` / ``access_control:`` / ``tool_call_control:``
          subsections in any combination. Validated via
          :meth:`provenex.Policy.from_text`.
        * Legacy access-control-only files: top-level ``rules:`` /
          ``defaults:``. Validated via :meth:`NativeYamlEvaluator.from_path`
          as a fallback so existing CI pipelines don't break.

    The unified layout is tried first; if it errors with a layout-level
    complaint (unknown top-level keys), we try the legacy path. If both
    fail, the unified error wins — it's the more informative one.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError as exc:
        return False, f"file not found: {exc.filename}"

    # Try the unified layout first. This handles everything new (tool-call admission
    # tool_call_control, verification-only files, etc.) and the common
    # single-half case where the file has ``access_control:`` at the top.
    unified_err: Optional[str] = None
    try:
        # Local import to avoid the Policy ↔ yaml_evaluator load-time
        # cycle Python would otherwise complain about.
        from .unified import Policy

        Policy.from_text(text, source=path)
        return True, None
    except (PolicyParseError, UnsupportedPolicyFeature) as exc:
        unified_err = str(exc)

    # Legacy fallback: a file with ``rules:`` at the top level (no
    # unified subsection) is still acceptable for retrieval callers.
    try:
        NativeYamlEvaluator.from_text(text, source=path)
        return True, None
    except (PolicyParseError, UnsupportedPolicyFeature):
        # Surface the unified error — it's usually more actionable.
        return False, unified_err
