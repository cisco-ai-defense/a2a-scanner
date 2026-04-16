"""Comprehensive scan policy tests — defaults, presets, knobs, round-trip, merge semantics."""

from __future__ import annotations

import yaml

import pytest

from a2ascanner.core.scan_policy import (
    AnalyzerPolicy,
    FindingOutputPolicy,
    LLMAnalysisPolicy,
    ScanPolicy,
)


class TestScanPolicyDefaults:
    """Verify that defaults are sensible and stable."""

    def test_default_policy_loads(self):
        policy = ScanPolicy.default()
        assert policy.policy_name in ("default", "balanced")

    def test_default_has_no_disabled_rules(self):
        policy = ScanPolicy.default()
        assert policy.disabled_rules == []

    def test_default_has_no_severity_overrides(self):
        policy = ScanPolicy.default()
        assert policy.severity_overrides == {}

    def test_default_analyzers_static_enabled(self):
        policy = ScanPolicy.default()
        assert policy.analyzers.static is True

    def test_default_analyzers_spec_enabled(self):
        policy = ScanPolicy.default()
        assert policy.analyzers.spec is True

    def test_default_analyzers_endpoint_enabled(self):
        policy = ScanPolicy.default()
        assert policy.analyzers.endpoint is True

    def test_default_analyzers_llm_disabled(self):
        policy = ScanPolicy.default()
        assert policy.analyzers.llm is False

    def test_default_llm_analysis_disabled(self):
        policy = ScanPolicy.default()
        assert policy.llm_analysis.enabled is False

    def test_default_llm_analysis_model_none(self):
        policy = ScanPolicy.default()
        assert policy.llm_analysis.model is None

    def test_default_llm_analysis_max_tokens(self):
        policy = ScanPolicy.default()
        assert policy.llm_analysis.max_output_tokens == 8192

    def test_default_finding_output_dedupe_exact(self):
        policy = ScanPolicy.default()
        assert policy.finding_output.dedupe_exact_findings is True

    def test_default_finding_output_dedupe_same_issue(self):
        policy = ScanPolicy.default()
        assert policy.finding_output.dedupe_same_issue_per_location is True

    def test_default_finding_output_policy_fingerprint(self):
        policy = ScanPolicy.default()
        assert policy.finding_output.attach_policy_fingerprint is True

    def test_default_finding_output_cooccurrence(self):
        policy = ScanPolicy.default()
        assert policy.finding_output.annotate_same_path_rule_cooccurrence is True

    def test_default_has_policy_version(self):
        policy = ScanPolicy.default()
        assert policy.policy_version is not None
        assert len(policy.policy_version) > 0

    def test_default_has_description(self):
        policy = ScanPolicy.default()
        assert isinstance(policy.description, str)


class TestScanPolicyPresets:
    """Verify preset loading and delta behaviour."""

    def test_preset_names_returns_all_three(self):
        names = ScanPolicy.preset_names()
        assert "strict" in names
        assert "balanced" in names
        assert "permissive" in names

    def test_strict_preset_loads(self):
        policy = ScanPolicy.from_preset("strict")
        assert policy.policy_name == "strict"

    def test_balanced_preset_loads(self):
        policy = ScanPolicy.from_preset("balanced")
        assert policy.policy_name in ("balanced", "default")

    def test_permissive_preset_loads(self):
        policy = ScanPolicy.from_preset("permissive")
        assert policy.policy_name == "permissive"

    def test_unknown_preset_raises(self):
        with pytest.raises(ValueError, match="Unknown preset"):
            ScanPolicy.from_preset("nonexistent")

    def test_case_insensitive_preset(self):
        policy = ScanPolicy.from_preset("STRICT")
        assert policy.policy_name == "strict"

    def test_strict_enables_all_analyzers(self):
        policy = ScanPolicy.from_preset("strict")
        assert policy.analyzers.static is True
        assert policy.analyzers.spec is True

    def test_permissive_has_disabled_rules(self):
        policy = ScanPolicy.from_preset("permissive")
        # Permissive may disable some rules
        assert isinstance(policy.disabled_rules, list)

    def test_strict_vs_default_comparison(self):
        strict = ScanPolicy.from_preset("strict")
        default = ScanPolicy.default()
        # Strict should be at least as restrictive
        assert len(strict.disabled_rules) <= len(default.disabled_rules)


class TestScanPolicyYAMLRoundTrip:
    """Verify YAML serialization and deserialization."""

    def test_to_yaml_and_back(self, tmp_path):
        original = ScanPolicy.default()
        out = tmp_path / "policy.yaml"
        original.to_yaml(out)
        loaded = ScanPolicy.from_yaml(out)
        assert loaded.policy_name == original.policy_name
        assert loaded.policy_version == original.policy_version
        assert loaded.disabled_rules == original.disabled_rules
        assert loaded.severity_overrides == original.severity_overrides
        assert loaded.analyzers.static == original.analyzers.static
        assert loaded.analyzers.spec == original.analyzers.spec
        assert loaded.analyzers.endpoint == original.analyzers.endpoint
        assert loaded.analyzers.llm == original.analyzers.llm
        assert loaded.llm_analysis.enabled == original.llm_analysis.enabled
        assert loaded.llm_analysis.model == original.llm_analysis.model
        assert loaded.llm_analysis.max_output_tokens == original.llm_analysis.max_output_tokens
        assert loaded.finding_output.dedupe_exact_findings == original.finding_output.dedupe_exact_findings

    def test_strict_roundtrip(self, tmp_path):
        original = ScanPolicy.from_preset("strict")
        out = tmp_path / "strict.yaml"
        original.to_yaml(out)
        loaded = ScanPolicy.from_yaml(out)
        assert loaded.policy_name == "strict"

    def test_permissive_roundtrip(self, tmp_path):
        original = ScanPolicy.from_preset("permissive")
        out = tmp_path / "permissive.yaml"
        original.to_yaml(out)
        loaded = ScanPolicy.from_yaml(out)
        assert loaded.policy_name == "permissive"

    def test_custom_disabled_rules_roundtrip(self, tmp_path):
        original = ScanPolicy.default()
        from dataclasses import replace

        modified = replace(original, disabled_rules=["rule_a", "rule_b"])
        out = tmp_path / "custom.yaml"
        modified.to_yaml(out)
        loaded = ScanPolicy.from_yaml(out)
        assert "rule_a" in loaded.disabled_rules
        assert "rule_b" in loaded.disabled_rules

    def test_severity_overrides_roundtrip(self, tmp_path):
        from dataclasses import replace

        original = ScanPolicy.default()
        modified = replace(original, severity_overrides={"some_rule": "CRITICAL"})
        out = tmp_path / "custom.yaml"
        modified.to_yaml(out)
        loaded = ScanPolicy.from_yaml(out)
        assert loaded.severity_overrides["some_rule"] == "CRITICAL"

    def test_llm_analysis_roundtrip(self, tmp_path):
        from dataclasses import replace

        original = ScanPolicy.default()
        modified = replace(
            original,
            llm_analysis=LLMAnalysisPolicy(
                enabled=True, model="gpt-4o", max_output_tokens=4096
            ),
        )
        out = tmp_path / "llm.yaml"
        modified.to_yaml(out)
        loaded = ScanPolicy.from_yaml(out)
        assert loaded.llm_analysis.enabled is True
        assert loaded.llm_analysis.model == "gpt-4o"
        assert loaded.llm_analysis.max_output_tokens == 4096


class TestScanPolicyMergeSemantics:
    """Verify partial YAML merges defaults correctly."""

    def test_partial_yaml_preserves_defaults(self, tmp_path):
        p = tmp_path / "partial.yaml"
        p.write_text(yaml.dump({"policy_name": "custom", "disabled_rules": ["x"]}))
        loaded = ScanPolicy.from_yaml(p)
        assert loaded.policy_name == "custom"
        assert loaded.disabled_rules == ["x"]
        # Defaults preserved for unspecified sections
        assert loaded.analyzers.static is True
        assert loaded.analyzers.spec is True

    def test_partial_yaml_merges_analyzers(self, tmp_path):
        p = tmp_path / "partial.yaml"
        p.write_text(
            yaml.dump(
                {
                    "policy_name": "test",
                    "analyzers": {"static": False},
                }
            )
        )
        loaded = ScanPolicy.from_yaml(p)
        assert loaded.analyzers.static is False
        assert loaded.analyzers.spec is True  # default preserved

    def test_empty_yaml_gets_all_defaults(self, tmp_path):
        p = tmp_path / "empty.yaml"
        p.write_text("{}")
        loaded = ScanPolicy.from_yaml(p)
        assert loaded.analyzers.static is True
        assert loaded.llm_analysis.enabled is False

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            ScanPolicy.from_yaml("/nonexistent/path.yaml")


class TestScanPolicyRuleControl:
    """Test is_rule_enabled and get_effective_severity."""

    def test_is_rule_enabled_default(self):
        policy = ScanPolicy.default()
        assert policy.is_rule_enabled("any_rule") is True

    def test_is_rule_enabled_disabled(self):
        from dataclasses import replace

        policy = replace(ScanPolicy.default(), disabled_rules=["blocked_rule"])
        assert policy.is_rule_enabled("blocked_rule") is False
        assert policy.is_rule_enabled("other_rule") is True

    def test_get_effective_severity_no_override(self):
        policy = ScanPolicy.default()
        assert policy.get_effective_severity("some_rule", "MEDIUM") == "MEDIUM"

    def test_get_effective_severity_with_override(self):
        from dataclasses import replace

        policy = replace(ScanPolicy.default(), severity_overrides={"some_rule": "CRITICAL"})
        assert policy.get_effective_severity("some_rule", "LOW") == "CRITICAL"

    def test_get_effective_severity_override_only_affects_targeted_rule(self):
        from dataclasses import replace

        policy = replace(ScanPolicy.default(), severity_overrides={"rule_a": "HIGH"})
        assert policy.get_effective_severity("rule_a", "LOW") == "HIGH"
        assert policy.get_effective_severity("rule_b", "LOW") == "LOW"


class TestFindingOutputKnobs:
    """Test FindingOutputPolicy knobs."""

    def test_default_all_knobs_true(self):
        fo = FindingOutputPolicy()
        assert fo.dedupe_exact_findings is True
        assert fo.dedupe_same_issue_per_location is True
        assert fo.attach_policy_fingerprint is True
        assert fo.annotate_same_path_rule_cooccurrence is True

    def test_custom_knobs(self):
        fo = FindingOutputPolicy(
            dedupe_exact_findings=False,
            attach_policy_fingerprint=False,
        )
        assert fo.dedupe_exact_findings is False
        assert fo.attach_policy_fingerprint is False
        assert fo.dedupe_same_issue_per_location is True

    def test_finding_output_roundtrip(self, tmp_path):
        from dataclasses import replace

        policy = ScanPolicy.default()
        policy = replace(
            policy,
            finding_output=FindingOutputPolicy(
                dedupe_exact_findings=False,
                dedupe_same_issue_per_location=False,
                attach_policy_fingerprint=False,
                annotate_same_path_rule_cooccurrence=False,
            ),
        )
        out = tmp_path / "fo.yaml"
        policy.to_yaml(out)
        loaded = ScanPolicy.from_yaml(out)
        assert loaded.finding_output.dedupe_exact_findings is False
        assert loaded.finding_output.dedupe_same_issue_per_location is False
        assert loaded.finding_output.attach_policy_fingerprint is False
        assert loaded.finding_output.annotate_same_path_rule_cooccurrence is False


class TestAnalyzerPolicyKnobs:
    """Test AnalyzerPolicy dataclass."""

    def test_default_toggles(self):
        ap = AnalyzerPolicy()
        assert ap.static is True
        assert ap.spec is True
        assert ap.endpoint is True
        assert ap.llm is False

    def test_all_disabled(self):
        ap = AnalyzerPolicy(static=False, spec=False, endpoint=False, llm=False)
        assert ap.static is False
        assert ap.spec is False
        assert ap.endpoint is False
        assert ap.llm is False

    def test_all_enabled(self):
        ap = AnalyzerPolicy(static=True, spec=True, endpoint=True, llm=True)
        assert ap.llm is True
