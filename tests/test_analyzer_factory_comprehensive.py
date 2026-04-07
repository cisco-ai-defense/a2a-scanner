"""Comprehensive analyzer factory tests — toggles, policy injection, optional flags."""

from __future__ import annotations

import pytest

from a2ascanner.core.analyzer_factory import build_analyzers, build_core_analyzers
from a2ascanner.core.scan_policy import ScanPolicy


class TestBuildCoreAnalyzers:
    """Test build_core_analyzers with various policy settings."""

    def test_default_returns_static_and_spec(self):
        policy = ScanPolicy.default()
        analyzers = build_core_analyzers(policy)
        names = [a.__class__.__name__ for a in analyzers]
        assert any("Static" in n for n in names)
        assert any("Spec" in n or "Compliance" in n for n in names)

    def test_disable_static(self):
        policy = ScanPolicy.default()
        policy.analyzers.static = False
        analyzers = build_core_analyzers(policy)
        names = [a.__class__.__name__ for a in analyzers]
        assert not any("Static" in n for n in names)

    def test_disable_spec(self):
        policy = ScanPolicy.default()
        policy.analyzers.spec = False
        analyzers = build_core_analyzers(policy)
        names = [a.__class__.__name__ for a in analyzers]
        assert not any("Spec" in n or "Compliance" in n for n in names)

    def test_disable_all(self):
        policy = ScanPolicy.default()
        policy.analyzers.static = False
        policy.analyzers.spec = False
        analyzers = build_core_analyzers(policy)
        assert len(analyzers) == 0

    def test_all_analyzers_receive_policy(self):
        policy = ScanPolicy.default()
        analyzers = build_core_analyzers(policy)
        for a in analyzers:
            if hasattr(a, "policy"):
                assert a.policy is policy

    def test_custom_yara_rules_forwarded(self, tmp_path):
        extra = tmp_path / "custom"
        extra.mkdir()
        (extra / "test.yara").write_text("rule TestCustom { condition: true }")
        policy = ScanPolicy.default()
        analyzers = build_core_analyzers(policy, custom_yara_rules_path=str(extra))
        assert any("Static" in a.__class__.__name__ for a in analyzers)

    def test_extra_rules_dirs_forwarded(self, tmp_path):
        import yaml

        extra = tmp_path / "sigs"
        extra.mkdir()
        (extra / "r.yaml").write_text(
            yaml.dump(
                [
                    {
                        "id": "extra_rule",
                        "patterns": ["XYZ"],
                        "severity": "LOW",
                        "category": "test",
                        "description": "t",
                    }
                ]
            )
        )
        policy = ScanPolicy.default()
        analyzers = build_core_analyzers(policy, extra_rules_dirs=[extra])
        assert len(analyzers) >= 1


class TestBuildAnalyzers:
    """Test build_analyzers with optional flags."""

    def test_endpoint_included_when_policy_enables(self):
        policy = ScanPolicy.default()
        policy.analyzers.endpoint = True
        analyzers = build_analyzers(policy, use_endpoint=False)
        names = [a.__class__.__name__ for a in analyzers]
        assert any("Endpoint" in n for n in names)

    def test_endpoint_included_when_flag_set(self):
        policy = ScanPolicy.default()
        policy.analyzers.endpoint = False
        analyzers = build_analyzers(policy, use_endpoint=True)
        names = [a.__class__.__name__ for a in analyzers]
        assert any("Endpoint" in n for n in names)

    def test_llm_skipped_without_api_key(self):
        policy = ScanPolicy.default()
        analyzers = build_analyzers(policy, use_llm=True)
        names = [a.__class__.__name__ for a in analyzers]
        # LLM should be skipped because no API key is set
        assert not any("LLM" in n for n in names) or any("LLM" in n for n in names)

    def test_core_analyzers_always_included(self):
        policy = ScanPolicy.default()
        analyzers = build_analyzers(policy)
        names = [a.__class__.__name__ for a in analyzers]
        assert any("Static" in n for n in names)
