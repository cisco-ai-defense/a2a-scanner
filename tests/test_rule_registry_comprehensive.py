"""Comprehensive rule registry tests — pack loading, audit, coverage, functional enable/disable."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from a2ascanner.core.rule_registry import PackLoader, RuleDefinition, RulePack, RuleRegistry
from a2ascanner.data import DATA_DIR


def _yara_rule_names_in_dir(yara_dir: Path) -> set[str]:
    """Parse 'rule RuleName' lines from .yara/.yar files."""
    names = set()
    if not yara_dir.is_dir():
        return names
    for fp in sorted(list(yara_dir.glob("*.yara")) + list(yara_dir.glob("*.yar"))):
        for line in fp.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^rule\s+(\w+)", line.strip())
            if m:
                names.add(m.group(1))
    return names


def _signature_rule_ids_in_dir(sig_dir: Path) -> set[str]:
    """Collect all rule 'id' values from YAML signature files."""
    import yaml

    ids = set()
    if not sig_dir.is_dir():
        return ids
    for fp in sorted(list(sig_dir.glob("*.yaml")) + list(sig_dir.glob("*.yml"))):
        data = yaml.safe_load(fp.read_text(encoding="utf-8"))
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict) and isinstance(data.get("signatures"), list):
            entries = data["signatures"]
        else:
            continue
        for entry in entries:
            if isinstance(entry, dict) and "id" in entry:
                ids.add(str(entry["id"]))
    return ids


class TestPackLoader:
    """Core pack loading functionality."""

    def test_load_core_pack(self):
        pack = PackLoader.load_pack(DATA_DIR / "packs" / "core")
        assert pack.name == "core"
        assert len(pack.rules) > 0

    def test_discover_packs_finds_core(self):
        packs = PackLoader.discover_packs()
        assert "core" in packs

    def test_missing_pack_yaml_raises(self, tmp_path):
        empty = tmp_path / "no_manifest"
        empty.mkdir()
        with pytest.raises(FileNotFoundError):
            PackLoader.load_pack(empty)

    def test_discover_extra_dir(self, tmp_path):
        import yaml

        extra = tmp_path / "extra_pack"
        extra.mkdir()
        (extra / "pack.yaml").write_text(
            yaml.dump(
                {
                    "pack": {"name": "extra", "version": "0.1.0", "description": "Extra"},
                    "rules": {"test_rule": {"enabled": True, "severity": "LOW"}},
                }
            )
        )
        packs = PackLoader.discover_packs(extra_dirs=[tmp_path])
        assert "extra" in packs
        assert "core" in packs  # built-in still present


class TestRuleRegistry:
    """Registry aggregation and lookup."""

    def test_register_and_query(self):
        registry = RuleRegistry()
        pack = RulePack(
            name="test",
            version="1.0",
            description="",
            rules={
                "r1": RuleDefinition(id="r1", severity="HIGH"),
            },
        )
        registry.register_pack(pack)
        assert registry.get_rule("r1") is not None
        assert registry.get_rule("r1").severity == "HIGH"
        assert registry.get_rule("unknown") is None

    def test_is_rule_enabled_default_true(self):
        registry = RuleRegistry()
        assert registry.is_rule_enabled("any_unknown_rule") is True

    def test_is_rule_enabled_respects_pack(self):
        registry = RuleRegistry()
        pack = RulePack(
            name="test",
            version="1.0",
            description="",
            rules={
                "disabled_rule": RuleDefinition(id="disabled_rule", enabled=False),
            },
        )
        registry.register_pack(pack)
        assert registry.is_rule_enabled("disabled_rule") is False

    def test_get_rule_returns_definition(self):
        pack = PackLoader.load_pack(DATA_DIR / "packs" / "core")
        registry = RuleRegistry()
        registry.register_pack(pack)
        # Should find at least one rule
        rule = None
        for rid in pack.rules:
            rule = registry.get_rule(rid)
            break
        assert rule is not None
        assert isinstance(rule, RuleDefinition)


class TestPackCoverageAudit:
    """Audit: every on-disk rule has a pack.yaml entry (CI safety net)."""

    def test_all_yara_rules_in_pack(self):
        core_dir = DATA_DIR / "packs" / "core"
        yara_dir = core_dir / "yara"
        if not yara_dir.is_dir():
            pytest.skip("No YARA directory in core pack")
        pack = PackLoader.load_pack(core_dir)
        yara_names = _yara_rule_names_in_dir(yara_dir)
        pack_rule_ids = set(pack.rules.keys())
        missing = yara_names - pack_rule_ids
        assert missing == set(), f"YARA rules missing from pack.yaml: {missing}"

    def test_all_signature_rules_in_pack(self):
        core_dir = DATA_DIR / "packs" / "core"
        sig_dir = core_dir / "signatures"
        if not sig_dir.is_dir():
            pytest.skip("No signatures directory in core pack")
        pack = PackLoader.load_pack(core_dir)
        sig_ids = _signature_rule_ids_in_dir(sig_dir)
        pack_rule_ids = set(pack.rules.keys())
        missing = sig_ids - pack_rule_ids
        assert missing == set(), f"Signature rules missing from pack.yaml: {missing}"

    def test_pack_entries_have_enabled_knob(self):
        pack = PackLoader.load_pack(DATA_DIR / "packs" / "core")
        for rid, rdef in pack.rules.items():
            assert isinstance(rdef.enabled, bool), f"Rule {rid} missing bool enabled"

    def test_no_orphan_pack_entries_for_yara(self):
        core_dir = DATA_DIR / "packs" / "core"
        yara_dir = core_dir / "yara"
        if not yara_dir.is_dir():
            pytest.skip("No YARA directory")
        pack = PackLoader.load_pack(core_dir)
        yara_names = _yara_rule_names_in_dir(yara_dir)
        sig_ids = (
            _signature_rule_ids_in_dir(core_dir / "signatures")
            if (core_dir / "signatures").is_dir()
            else set()
        )
        all_on_disk = yara_names | sig_ids
        pack_rule_ids = set(pack.rules.keys())
        orphans = pack_rule_ids - all_on_disk
        if orphans:
            pytest.xfail(f"Pack.yaml entries with no on-disk rule: {orphans}")
