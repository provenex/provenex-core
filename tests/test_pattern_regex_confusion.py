"""Tests for the v0.8.1 fnmatch-glob-vs-regex parse guard.

The YAML DSL's ``matches_pattern`` / ``not_matches_pattern`` use
``fnmatch`` (glob), not ``re`` (regex). An operator who writes
``"*(api_key|password)*"`` gets a silently-broken rule because fnmatch
treats ``(``, ``)``, ``|`` as literal characters. v0.8.1 fails this at
parse time with a clear hint to write one rule per pattern.

The guard runs at policy-load: ``Policy.from_text(...)``,
``Policy.from_yaml(...)``, ``validate_policy_file(...)``, and the CLI's
``provenex policy validate`` all surface the error before any rule
ever runs at decision time.
"""

from __future__ import annotations

import pytest

from provenex.policy.evaluator import PolicyParseError
from provenex.policy.unified import Policy
from provenex.policy.yaml_evaluator import validate_policy_file


_POLICY_TEMPLATE = """
version: 1
policy_id: regex-confusion-test
tool_call_control:
  rules:
    - name: rule_under_test
      when: {{ tool.name: web_search }}
      require:
        tool.parameters.q:
          not_matches_pattern: "{pattern}"
      on_violation: deny
  defaults:
    unknown_metadata: allow
"""


@pytest.mark.parametrize(
    "pattern",
    [
        "*(api_key|password)*",       # the README's original broken example
        "*api_key|password*",          # bare pipe
        "(secret)",                    # bare parens
        "*foo(bar)baz*",
        "a|b",
    ],
)
def test_regex_confusion_patterns_fail_at_parse(pattern):
    text = _POLICY_TEMPLATE.format(pattern=pattern)
    with pytest.raises(PolicyParseError) as exc:
        Policy.from_text(text, source="test")
    msg = str(exc.value)
    # The error must name the operator path, name the regex char(s),
    # and hint at the one-rule-per-pattern fix.
    assert "not_matches_pattern" in msg
    assert "fnmatch" in msg
    assert "one rule per pattern" in msg


@pytest.mark.parametrize(
    "pattern",
    [
        "*api_key=*",                  # the v0.8.1 demo's pattern
        "*password*",
        "*.example.com",
        "*",                            # match-anything
        "[abc]*",                       # character class is legitimate glob
        "?eta?",                        # single-char wildcards
    ],
)
def test_well_formed_globs_parse_clean(pattern):
    text = _POLICY_TEMPLATE.format(pattern=pattern)
    policy = Policy.from_text(text, source="test")
    assert policy.tool_call_control is not None


def test_matches_pattern_path_also_guarded(tmp_path):
    """Same guard applies to ``matches_pattern`` (the positive form)."""
    text = """
version: 1
policy_id: regex-confusion-test-positive
tool_call_control:
  rules:
    - name: positive_rule
      when: { tool.name: web_search }
      require:
        tool.target_system:
          matches_pattern: "(google|bing).com"
      on_violation: deny
  defaults:
    unknown_metadata: allow
"""
    with pytest.raises(PolicyParseError) as exc:
        Policy.from_text(text, source="test")
    assert "matches_pattern" in str(exc.value)
    assert "one rule per pattern" in str(exc.value)


def test_validate_policy_file_surfaces_the_error(tmp_path):
    """``validate_policy_file`` is what ``provenex policy validate``
    runs at the CLI; it must surface the same error."""
    policy_path = tmp_path / "broken.yaml"
    policy_path.write_text(_POLICY_TEMPLATE.format(pattern="*(a|b)*"))
    ok, err = validate_policy_file(str(policy_path))
    assert ok is False
    assert err is not None
    assert "fnmatch" in err
    assert "one rule per pattern" in err


def test_chunk_access_control_pattern_also_guarded():
    """The same guard applies to chunk-side ``access_control`` rules."""
    text = """
version: 1
policy_id: regex-confusion-test-chunks
access_control:
  rules:
    - name: residency_glob_guard
      when:
        request.jurisdiction: EU
      require:
        chunk.metadata.region:
          matches_pattern: "(EU|EEA)"
      on_violation: deny
  defaults:
    unknown_metadata: deny
"""
    with pytest.raises(PolicyParseError) as exc:
        Policy.from_text(text, source="test")
    assert "fnmatch" in str(exc.value)
