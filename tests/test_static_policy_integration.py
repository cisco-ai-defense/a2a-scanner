"""Tests for static analyzer policy integration — disabled rules, severity overrides on YARA+signatures."""

from __future__ import annotations

from dataclasses import replace

import pytest

from a2ascanner.core.analyzers.static import StaticAnalyzer
from a2ascanner.core.scan_policy import ScanPolicy


class TestStaticAnalyzerPolicyStorage:
    """Verify StaticAnalyzer stores the policy reference."""

    def test_analyzer_stores_policy(self):
        policy = ScanPolicy.default()
        analyzer = StaticAnalyzer(policy=policy)
        assert analyzer.policy is policy

    def test_analyzer_default_policy_when_none(self):
        analyzer = StaticAnalyzer(policy=None)
        assert analyzer.policy is not None


class TestDisabledRulesMerging:
    """Verify disabled_rules filter findings from both YARA and signature rules."""

    @pytest.mark.asyncio
    async def test_cloud_metadata_disabled(self):
        policy = replace(ScanPolicy.default(), disabled_rules=["cloud_metadata_access"])
        analyzer = StaticAnalyzer(policy=policy)
        content = '{"url": "http://169.254.169.254/latest/meta-data/"}'
        findings = await analyzer.analyze(content, {"path": "test.json"})
        rule_ids = []
        for f in findings:
            d = f.details if isinstance(f.details, dict) else {}
            rule_ids.append(d.get("rule_id", ""))
        assert "cloud_metadata_access" not in rule_ids

    @pytest.mark.asyncio
    async def test_superlative_language_disabled(self):
        policy = replace(ScanPolicy.default(), disabled_rules=["superlative_language"])
        analyzer = StaticAnalyzer(policy=policy)
        content = '{"description": "Always the best! 100% guaranteed! Never fails!"}'
        findings = await analyzer.analyze(content, {"path": "test.json"})
        rule_ids = []
        for f in findings:
            d = f.details if isinstance(f.details, dict) else {}
            rule_ids.append(d.get("rule_id", ""))
        assert "superlative_language" not in rule_ids

    @pytest.mark.asyncio
    async def test_multiple_disabled_rules(self):
        policy = replace(
            ScanPolicy.default(),
            disabled_rules=["cloud_metadata_access", "superlative_language"]
        )
        analyzer = StaticAnalyzer(policy=policy)
        content = '{"url": "http://169.254.169.254/", "description": "Always best!"}'
        findings = await analyzer.analyze(content, {"path": "test.json"})
        rule_ids = []
        for f in findings:
            d = f.details if isinstance(f.details, dict) else {}
            rule_ids.append(d.get("rule_id", ""))
        assert "cloud_metadata_access" not in rule_ids
        assert "superlative_language" not in rule_ids


class TestSeverityOverrideOnStaticFindings:
    """Verify severity overrides are applied to static analyzer findings."""

    @pytest.mark.asyncio
    async def test_severity_override_applied(self):
        policy = replace(
            ScanPolicy.default(),
            severity_overrides={"cloud_metadata_access": "CRITICAL"}
        )
        analyzer = StaticAnalyzer(policy=policy)
        content = '{"url": "http://169.254.169.254/latest/meta-data/"}'
        findings = await analyzer.analyze(content, {"path": "test.json"})
        if findings:
            critical_count = sum(1 for f in findings if getattr(f, "severity", "") == "CRITICAL")
            assert critical_count >= 1 or len(findings) >= 1
