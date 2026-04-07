"""Tests for the interactive scan wizard imports and constants."""

from __future__ import annotations


class TestWizardImports:
    """Verify wizard module is importable and has expected exports."""

    def test_wizard_imports(self):
        from a2ascanner.cli.wizard import run_wizard
        assert callable(run_wizard)

    def test_format_choices(self):
        from a2ascanner.cli.wizard import _FORMAT_CHOICES
        assert "json" in _FORMAT_CHOICES
        assert "sarif" in _FORMAT_CHOICES
        assert "markdown" in _FORMAT_CHOICES
        assert "table" in _FORMAT_CHOICES
        assert "html" in _FORMAT_CHOICES
        assert "summary" in _FORMAT_CHOICES

    def test_target_choices(self):
        from a2ascanner.cli.wizard import _TARGET_CHOICES
        assert "file" in _TARGET_CHOICES
        assert "directory" in _TARGET_CHOICES
        assert "endpoint" in _TARGET_CHOICES
        assert "registry" in _TARGET_CHOICES

    def test_known_analyzers_set(self):
        from a2ascanner.cli.wizard import _KNOWN_ANALYZERS
        assert isinstance(_KNOWN_ANALYZERS, frozenset)
        assert "static_analyzer" in _KNOWN_ANALYZERS
        assert "spec" in _KNOWN_ANALYZERS
        assert "endpoint" in _KNOWN_ANALYZERS

    def test_wizard_uses_build_parser(self):
        """Wizard must use the main CLI parser for dispatch."""
        import inspect
        from a2ascanner.cli import wizard
        source = inspect.getsource(wizard.run_wizard)
        assert "build_parser" in source
        assert "_dispatch" in source


class TestInteractiveCLI:
    """Test interactive CLI subcommand registration."""

    def test_interactive_command_registered(self):
        from a2ascanner.cli.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["interactive"])
        assert args.command == "interactive"
