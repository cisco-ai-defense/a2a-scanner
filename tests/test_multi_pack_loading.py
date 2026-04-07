"""Tests for multi-pack loading, extra rules dirs, and CLI --rule-packs integration."""

from __future__ import annotations

import pytest
import yaml

from a2ascanner.core.rules.patterns import RuleLoader


class TestExtractRuleList:
    """Test RuleLoader._extract_rule_list for various YAML shapes."""

    def test_flat_list(self):
        data = [{"id": "r1", "patterns": ["x"]}, {"id": "r2", "patterns": ["y"]}]
        result = RuleLoader._extract_rule_list(data)
        assert len(result) == 2
        assert result[0]["id"] == "r1"

    def test_wrapped_in_signatures_key(self):
        data = {"signatures": [{"id": "r1", "patterns": ["x"]}]}
        result = RuleLoader._extract_rule_list(data)
        assert len(result) == 1

    def test_none_returns_empty(self):
        assert RuleLoader._extract_rule_list(None) == []

    def test_non_dict_non_list_returns_empty(self):
        assert RuleLoader._extract_rule_list("not a dict or list") == []

    def test_dict_without_signatures_returns_empty(self):
        assert RuleLoader._extract_rule_list({"other_key": [1, 2]}) == []


class TestRuleLoaderExtraDirs:
    """Test loading rules from extra directories."""

    def test_extra_dir_adds_rules(self, tmp_path):
        extra = tmp_path / "extra_sigs"
        extra.mkdir()
        (extra / "custom.yaml").write_text(
            yaml.dump(
                [
                    {
                        "id": "custom_rule_1",
                        "category": "test",
                        "severity": "LOW",
                        "description": "A test rule",
                        "patterns": ["CUSTOM_PATTERN"],
                    },
                ]
            )
        )
        loader = RuleLoader(extra_rules_dirs=[extra])
        rules = loader.load()
        rule_ids = [r.id for r in rules]
        assert "custom_rule_1" in rule_ids

    def test_extra_dir_nonexistent_ignored(self, tmp_path):
        fake = tmp_path / "nonexistent"
        loader = RuleLoader(extra_rules_dirs=[fake])
        rules = loader.load()
        assert isinstance(rules, list)


class TestPackDiscovery:
    """Test pack discovery and resolution functions."""

    def test_list_available_packs(self):
        from a2ascanner.data import list_available_packs

        packs = list_available_packs()
        assert isinstance(packs, list)
        # core is excluded from list_available_packs
        assert "core" not in packs

    def test_resolve_rule_packs_core_skipped(self):
        from a2ascanner.data import resolve_rule_packs

        result = resolve_rule_packs(["core"])
        assert result == []

    def test_resolve_rule_packs_unknown_raises(self):
        from a2ascanner.data import resolve_rule_packs

        with pytest.raises(ValueError, match="has no signatures"):
            resolve_rule_packs(["nonexistent_pack_xyz"])


class TestAnalyzerFactoryExtraRules:
    """Test that extra rules dirs flow through to the analyzer factory."""

    def test_custom_rules_forwarded_to_static(self, tmp_path):
        from a2ascanner.core.analyzer_factory import build_core_analyzers
        from a2ascanner.core.scan_policy import ScanPolicy

        extra = tmp_path / "sigs"
        extra.mkdir()
        (extra / "extra.yaml").write_text(
            yaml.dump(
                [
                    {
                        "id": "extra_check",
                        "category": "test",
                        "severity": "LOW",
                        "description": "test",
                        "patterns": ["EXTRA_TOKEN"],
                    },
                ]
            )
        )
        policy = ScanPolicy.default()
        analyzers = build_core_analyzers(policy, extra_rules_dirs=[extra])
        static = next((a for a in analyzers if "Static" in a.__class__.__name__), None)
        assert static is not None


class TestCLIRulePacks:
    """Test --rule-packs CLI argument wiring."""

    def test_rule_packs_flag_registered(self):
        from a2ascanner.cli.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "test.json", "--rule-packs", "core"])
        assert "core" in args.rule_packs

    def test_rule_packs_list_handler(self):
        from a2ascanner.cli.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "test.json", "--rule-packs", "list"])
        assert "list" in args.rule_packs
