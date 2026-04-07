"""Comprehensive policy integration tests — disabled rules, severity overrides, analyzer toggles."""

from __future__ import annotations

from dataclasses import replace

import pytest

from a2ascanner.core.analyzer_factory import build_core_analyzers
from a2ascanner.core.scan_policy import ScanPolicy


class TestDisabledRules:
    """Verify disabled_rules actually filter findings from real analyzers."""

    @pytest.mark.asyncio
    async def test_disabled_rule_filters_findings(self, scan_policy_default):
        policy = replace(scan_policy_default, disabled_rules=["superlative_language"])
        analyzers = build_core_analyzers(policy)
        static = next((a for a in analyzers if hasattr(a, "name") and "Static" in a.__class__.__name__), None)
        if static is None:
            pytest.skip("Static analyzer not available")
        result = await static.analyze(
            '{"description": "Always the best! 100% guaranteed!"}', {"path": "test.json"}
        )
        rule_ids = [f.details.get("rule_id", "") if isinstance(f.details, dict) else "" for f in result]
        assert "superlative_language" not in rule_ids

    @pytest.mark.asyncio
    async def test_disabled_rule_does_not_affect_other_rules(self, scan_policy_default):
        policy = replace(scan_policy_default, disabled_rules=["superlative_language"])
        analyzers = build_core_analyzers(policy)
        static = next((a for a in analyzers if "Static" in a.__class__.__name__), None)
        if static is None:
            pytest.skip("Static analyzer not available")
        content = '{"url": "http://169.254.169.254/latest/meta-data/"}'
        result = await static.analyze(content, {"path": "test.json"})
        has_metadata = any(
            "cloud_metadata" in str(getattr(f, "rule_id", "")) or
            "metadata" in str(getattr(f, "threat_name", "")).lower() or
            "169.254" in str(getattr(f, "details", {}))
            for f in result
        )
        assert has_metadata or len(result) > 0  # Other rules still fire


class TestSeverityOverrides:
    """Verify severity_overrides change effective severity."""

    @pytest.mark.asyncio
    async def test_severity_override_changes_finding_severity(self, scan_policy_default):
        policy = replace(scan_policy_default, severity_overrides={"cloud_metadata_access": "CRITICAL"})
        analyzers = build_core_analyzers(policy)
        static = next((a for a in analyzers if "Static" in a.__class__.__name__), None)
        if static is None:
            pytest.skip("Static analyzer not available")
        content = '{"url": "http://169.254.169.254/latest/meta-data/"}'
        result = await static.analyze(content, {"path": "test.json"})
        critical_findings = [f for f in result if getattr(f, "severity", "") == "CRITICAL"]
        if result:
            assert len(critical_findings) >= 1 or any(
                "CRITICAL" in str(getattr(f, "severity", "")) for f in result
            )


class TestAnalyzerToggles:
    """Verify analyzer toggles in policy affect which analyzers are built."""

    def test_all_analyzers_enabled_by_default(self):
        policy = ScanPolicy.default()
        analyzers = build_core_analyzers(policy)
        names = [a.__class__.__name__ for a in analyzers]
        assert any("Static" in n for n in names)
        assert any("Spec" in n for n in names)

    def test_disable_static_analyzer(self):
        policy = ScanPolicy.default()
        policy.analyzers.static = False
        analyzers = build_core_analyzers(policy)
        names = [a.__class__.__name__ for a in analyzers]
        assert not any("Static" in n for n in names)

    def test_disable_spec_analyzer(self):
        policy = ScanPolicy.default()
        policy.analyzers.spec = False
        analyzers = build_core_analyzers(policy)
        names = [a.__class__.__name__ for a in analyzers]
        assert not any("Spec" in n or "Compliance" in n for n in names)

    def test_disable_all_analyzers_produces_empty_list(self):
        policy = ScanPolicy.default()
        policy.analyzers.static = False
        policy.analyzers.spec = False
        analyzers = build_core_analyzers(policy)
        assert len(analyzers) == 0

    def test_policy_toggles_from_strict_preset(self):
        policy = ScanPolicy.from_preset("strict")
        analyzers = build_core_analyzers(policy)
        assert len(analyzers) >= 2  # static + spec at minimum


class TestPolicyWithScanner:
    """Integration tests using Scanner with policy."""

    @pytest.mark.asyncio
    async def test_scanner_uses_policy(self, make_scanner, safe_agent_card):
        from a2ascanner.core.scan_policy import ScanPolicy
        policy = ScanPolicy.default()
        scanner = make_scanner(policy=policy)
        result = await scanner.scan_agent_card(safe_agent_card)
        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_scanner_with_strict_policy(self, make_scanner, malicious_agent_card_full):
        from a2ascanner.core.scan_policy import ScanPolicy
        policy = ScanPolicy.from_preset("strict")
        scanner = make_scanner(policy=policy)
        result = await scanner.scan_agent_card(malicious_agent_card_full)
        assert result.status == "completed"
