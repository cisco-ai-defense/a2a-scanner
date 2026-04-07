"""Tests for the policy TUI and interactive wizard imports and contracts."""

from __future__ import annotations

import inspect
import subprocess
import sys

import pytest


class TestTUIImports:
    """Verify policy_tui module is importable and has expected exports."""

    def test_policy_tui_imports(self):
        from a2ascanner.cli.policy_tui import PolicyConfigApp, run_policy_tui
        assert PolicyConfigApp is not None
        assert callable(run_policy_tui)

    def test_policy_config_app_instantiates(self):
        from a2ascanner.cli.policy_tui import PolicyConfigApp
        app = PolicyConfigApp(output_path="test_policy.yaml", input_path=None)
        assert app.output_path == "test_policy.yaml"
        assert app.input_path is None

    def test_policy_config_app_with_input_path(self, tmp_path):
        from a2ascanner.core.scan_policy import ScanPolicy
        policy = ScanPolicy.default()
        p = tmp_path / "input.yaml"
        policy.to_yaml(p)

        from a2ascanner.cli.policy_tui import PolicyConfigApp
        app = PolicyConfigApp(output_path="out.yaml", input_path=str(p))
        assert app.input_path == str(p)
        assert app.policy.policy_name == policy.policy_name

    def test_run_policy_tui_signature(self):
        from a2ascanner.cli.policy_tui import run_policy_tui
        sig = inspect.signature(run_policy_tui)
        params = list(sig.parameters.keys())
        assert "output_path" in params
        assert "input_path" in params

    def test_policy_config_app_exit_code_default(self):
        from a2ascanner.cli.policy_tui import PolicyConfigApp
        app = PolicyConfigApp(output_path="x.yaml", input_path=None)
        assert app.exit_code == 0


class TestConfigurePolicyCLI:
    """Test configure-policy CLI subcommand registration."""

    def test_configure_policy_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "a2ascanner.cli.cli", "configure-policy", "--help"],
            capture_output=True, text=True, timeout=30,
        )
        combined = result.stdout + result.stderr
        assert result.returncode == 0
        assert "--input" in combined or "-i" in combined
        assert "--output" in combined or "-o" in combined

    def test_configure_policy_registered(self):
        from a2ascanner.cli.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["configure-policy", "-o", "out.yaml", "-i", "in.yaml"])
        assert args.command == "configure-policy"
        assert args.policy_tui_output == "out.yaml"
        assert args.policy_tui_input == "in.yaml"


class TestSeverityOptions:
    """Test that severity options are correctly defined."""

    def test_severity_options_tuple(self):
        from a2ascanner.cli.policy_tui import _SEVERITY_OPTIONS
        assert isinstance(_SEVERITY_OPTIONS, tuple)
        assert "CRITICAL" in _SEVERITY_OPTIONS
        assert "HIGH" in _SEVERITY_OPTIONS
        assert "MEDIUM" in _SEVERITY_OPTIONS
        assert "LOW" in _SEVERITY_OPTIONS


class TestPolicyConfigAppPresets:
    """Test preset loading in the TUI app."""

    def test_default_preset_is_balanced(self):
        from a2ascanner.cli.policy_tui import PolicyConfigApp
        app = PolicyConfigApp(output_path="x.yaml", input_path=None)
        assert app.policy.policy_name in ("balanced", "default")

    def test_parse_disabled_rules(self):
        from a2ascanner.cli.policy_tui import PolicyConfigApp
        app = PolicyConfigApp(output_path="x.yaml", input_path=None)
        rules = app._parse_disabled_rules("rule_a\nrule_b\n  \nrule_c")
        assert rules == ["rule_a", "rule_b", "rule_c"]

    def test_parse_disabled_rules_empty(self):
        from a2ascanner.cli.policy_tui import PolicyConfigApp
        app = PolicyConfigApp(output_path="x.yaml", input_path=None)
        rules = app._parse_disabled_rules("")
        assert rules == []

    def test_parse_overrides(self):
        from a2ascanner.cli.policy_tui import PolicyConfigApp
        app = PolicyConfigApp(output_path="x.yaml", input_path=None)
        overrides = app._parse_overrides("rule_a: HIGH\nrule_b: LOW\n# comment\nbad_line")
        assert overrides == {"rule_a": "HIGH", "rule_b": "LOW"}

    def test_parse_overrides_invalid_severity_ignored(self):
        from a2ascanner.cli.policy_tui import PolicyConfigApp
        app = PolicyConfigApp(output_path="x.yaml", input_path=None)
        overrides = app._parse_overrides("rule_a: BANANA\nrule_b: MEDIUM")
        assert overrides == {"rule_b": "MEDIUM"}
