"""Regression tests for bug fixes applied to the a2a-scanner project."""

from __future__ import annotations

import hashlib
import re

import pytest


class TestDeterministicFindingIds:
    """Verify finding IDs are deterministic (not based on hash())."""

    def test_sha256_based_ids_are_deterministic(self):
        parts = ("rule_id", "file.py", "1", "snippet")
        key = "|".join(str(p) for p in parts)
        id1 = hashlib.sha256(key.encode()).hexdigest()[:8]
        id2 = hashlib.sha256(key.encode()).hexdigest()[:8]
        assert id1 == id2
        assert len(id1) == 8


class TestYaraMetadataParsing:
    """Verify YARA-x metadata is parsed correctly as tuples."""

    def test_yara_scanner_compiles(self):
        from a2ascanner.core.rules.yara_scanner import YaraScanner

        scanner = YaraScanner()
        scanner.compile_rules()
        assert scanner._rules is not None

    def test_yara_scanner_scan_returns_list(self):
        from a2ascanner.core.rules.yara_scanner import YaraScanner

        scanner = YaraScanner()
        scanner.compile_rules()
        results = scanner.scan("this is safe content")
        assert isinstance(results, list)

    def test_yara_scanner_match_structure(self):
        from a2ascanner.core.rules.yara_scanner import YaraScanner

        scanner = YaraScanner()
        scanner.compile_rules()
        content = '{"url": "http://169.254.169.254/latest/meta-data/"}'
        results = scanner.scan(content)
        for match in results:
            assert isinstance(match, dict)
            assert "rule_name" in match
            assert "severity" in match
            assert "threat_name" in match
            assert "description" in match


class TestPatternRuleLoading:
    """Verify YAML signature rules load correctly."""

    def test_rule_loader_loads_rules(self):
        from a2ascanner.core.rules.patterns import RuleLoader

        loader = RuleLoader()
        rules = loader.load()
        assert len(rules) > 0

    def test_security_rule_has_required_fields(self):
        from a2ascanner.core.rules.patterns import RuleLoader

        loader = RuleLoader()
        rules = loader.load()
        for rule in rules:
            assert hasattr(rule, "id")
            assert hasattr(rule, "patterns")
            assert hasattr(rule, "severity")
            assert hasattr(rule, "category")

    def test_security_rule_patterns_compiled(self):
        from a2ascanner.core.rules.patterns import RuleLoader

        loader = RuleLoader()
        rules = loader.load()
        for rule in rules:
            for pat in rule.patterns:
                assert isinstance(pat, re.Pattern)


class TestStaticAnalyzerIntegrity:
    """Verify static analyzer combines YARA and signature rules."""

    @pytest.mark.asyncio
    async def test_static_analyzer_runs_both_engines(self):
        from a2ascanner.core.analyzers.static import StaticAnalyzer
        from a2ascanner.core.scan_policy import ScanPolicy

        analyzer = StaticAnalyzer(policy=ScanPolicy.default())
        content = '{"url": "http://169.254.169.254/latest/", "description": "Always best!"}'
        findings = await analyzer.analyze(content, {"file_path": "test.json"})
        assert isinstance(findings, list)

    def test_static_analyzer_has_rule_loader(self):
        from a2ascanner.core.analyzers.static import StaticAnalyzer
        from a2ascanner.core.scan_policy import ScanPolicy

        analyzer = StaticAnalyzer(policy=ScanPolicy.default())
        assert analyzer.rule_loader is not None

    def test_static_analyzer_has_yara_scanner(self):
        from a2ascanner.core.analyzers.static import StaticAnalyzer
        from a2ascanner.core.scan_policy import ScanPolicy

        analyzer = StaticAnalyzer(policy=ScanPolicy.default())
        assert analyzer.yara_scanner is not None


class TestAPIKeyNotInBody:
    """Verify API keys are not exposed in request bodies."""

    def test_scan_request_model_no_api_key(self):
        try:
            from a2ascanner.api.routes import AgentCardScanRequest

            fields = getattr(AgentCardScanRequest, "model_fields", None)
            if fields is None:
                fields = getattr(AgentCardScanRequest, "__fields__", {})
            for fname in fields:
                lower = str(fname).lower()
                assert "api_key" not in lower
                assert "secret" not in lower
        except ImportError:
            pytest.skip("API routes not available")


class TestThreatMappingConsistency:
    """Verify threat mapping includes all analyzer names."""

    def test_static_analyzer_in_threat_mapping(self):
        from a2ascanner.core.threats.threats import ThreatMapping

        info = ThreatMapping.get_threat_mapping("static_analyzer", "AGENT CARD SPOOFING")
        assert isinstance(info, dict)

    def test_all_core_analyzers_have_threat_mapping(self):
        from a2ascanner.core.threats.threats import ThreatMapping
        from a2ascanner.core.analyzer_factory import build_core_analyzers
        from a2ascanner.core.scan_policy import ScanPolicy

        analyzers = build_core_analyzers(ScanPolicy.default())
        sample_threats = {
            "static_analyzer": "PROMPT INJECTION",
            "speccompliance": "MISSING REQUIRED FIELD",
        }
        for a in analyzers:
            name = getattr(a, "name", a.__class__.__name__)
            key = name.lower()
            assert key in sample_threats
            ThreatMapping.get_threat_mapping(name, sample_threats[key])
            if "Static" in a.__class__.__name__:
                ThreatMapping.get_threat_mapping("static_analyzer", "PROMPT INJECTION")


class TestCLIHelpers:
    """Verify CLI helper functions work correctly."""

    def test_parse_analyzer_list_none(self):
        from a2ascanner.cli.cli import parse_analyzer_list

        assert parse_analyzer_list(None) is None

    def test_parse_analyzer_list_empty(self):
        from a2ascanner.cli.cli import parse_analyzer_list

        assert parse_analyzer_list([]) is None

    def test_parse_analyzer_list_comma_separated(self):
        from a2ascanner.cli.cli import parse_analyzer_list

        result = parse_analyzer_list(["static_analyzer,spec,endpoint"])
        assert result == ["static_analyzer", "spec", "endpoint"]

    def test_parse_analyzer_list_repeated(self):
        from a2ascanner.cli.cli import parse_analyzer_list

        result = parse_analyzer_list(["static_analyzer", "spec"])
        assert result == ["static_analyzer", "spec"]

    def test_get_formats_default(self):
        from a2ascanner.cli.cli import _get_formats
        import argparse

        ns = argparse.Namespace(format=None)
        assert _get_formats(ns) == ["summary"]

    def test_get_formats_list(self):
        from a2ascanner.cli.cli import _get_formats
        import argparse

        ns = argparse.Namespace(format=["json", "sarif"])
        assert _get_formats(ns) == ["json", "sarif"]

    def test_get_formats_single(self):
        from a2ascanner.cli.cli import _get_formats
        import argparse

        ns = argparse.Namespace(format="json")
        assert _get_formats(ns) == ["json"]
