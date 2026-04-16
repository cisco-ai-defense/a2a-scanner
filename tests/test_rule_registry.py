# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for pack manifests, PackLoader, and RuleRegistry."""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest
import yaml

from a2ascanner.core.rule_registry import PackLoader, RuleDefinition, RulePack, RuleRegistry
from a2ascanner.data import DATA_DIR

_PACKS_DIR = DATA_DIR / "packs"
_YARA_RULE_LINE = re.compile(r"^\s*rule\s+(\w+)\s*(?:\{|$)")


def _yara_rule_names_in_dir(yara_dir: Path) -> set[str]:
    names: set[str] = set()
    for path in sorted(yara_dir.glob("*.yara")) + sorted(yara_dir.glob("*.yar")):
        for line in path.read_text(encoding="utf-8").splitlines():
            m = _YARA_RULE_LINE.match(line)
            if m:
                names.add(m.group(1))
    return names


class TestPackLoader:
    def test_load_core_pack(self) -> None:
        pack = PackLoader.load_pack(_PACKS_DIR / "core")
        assert pack.name == "core"
        assert len(pack.rules) > 0
        assert pack.version
        assert isinstance(pack.rules["AgentCard_EmojiSpam"], RuleDefinition)

    def test_discover_packs(self) -> None:
        packs = PackLoader.discover_packs()
        assert "core" in packs
        assert packs["core"].name == "core"
        assert len(packs["core"].rules) > 0

    def test_discover_extra_dir_overrides_name(self, tmp_path: Path) -> None:
        """Later roots override packs with the same name."""
        extra = tmp_path / "overlay"
        extra.mkdir()
        (extra / "core").mkdir()
        (extra / "core" / "pack.yaml").write_text(
            textwrap.dedent(
                """
                pack:
                  name: core
                  version: "9.9.9"
                  description: "overlay"
                rules:
                  OverlayOnlyRule:
                    enabled: false
                    severity: LOW
                """
            ).strip(),
            encoding="utf-8",
        )
        merged = PackLoader.discover_packs(extra_dirs=[extra])
        assert merged["core"].version == "9.9.9"
        assert "OverlayOnlyRule" in merged["core"].rules
        assert merged["core"].rules["OverlayOnlyRule"].enabled is False


class TestRuleRegistry:
    def test_register_and_query(self) -> None:
        registry = RuleRegistry()
        pack = PackLoader.load_pack(_PACKS_DIR / "core")
        registry.register_pack(pack)
        assert len(registry.packs) == 1
        assert registry.get_rule("nonexistent_pack_rule") is None

    def test_is_rule_enabled_default(self) -> None:
        registry = RuleRegistry()
        assert registry.is_rule_enabled("nonexistent_rule") is True

    def test_get_rule_returns_definition(self) -> None:
        registry = RuleRegistry()
        pack = PackLoader.load_pack(_PACKS_DIR / "core")
        registry.register_pack(pack)
        rule = registry.get_rule("PromptInjectionAttempt")
        assert rule is not None
        assert rule.id == "PromptInjectionAttempt"
        assert rule.severity == "HIGH"

    def test_is_rule_enabled_respects_pack(self, tmp_path: Path) -> None:
        pdir = tmp_path / "custom"
        pdir.mkdir()
        (pdir / "pack.yaml").write_text(
            yaml.safe_dump(
                {
                    "pack": {"name": "custom", "version": "1", "description": "t"},
                    "rules": {"r1": {"enabled": False, "severity": "LOW"}},
                }
            ),
            encoding="utf-8",
        )
        registry = RuleRegistry()
        registry.register_pack(PackLoader.load_pack(pdir))
        assert registry.is_rule_enabled("r1") is False
        assert registry.get_rule("r1") is not None


class TestYaraRulesAudit:
    """Every YARA rule name in a pack must be listed in that pack's pack.yaml."""

    def test_yara_rule_names_have_pack_yaml_entries(self) -> None:
        for pack_dir in sorted(_PACKS_DIR.iterdir()):
            if not pack_dir.is_dir():
                continue
            yara_dir = pack_dir / "yara"
            manifest = pack_dir / "pack.yaml"
            if not yara_dir.is_dir() or not manifest.is_file():
                continue
            pack = PackLoader.load_pack(pack_dir)
            yara_names = _yara_rule_names_in_dir(yara_dir)
            missing = sorted(yara_names - set(pack.rules))
            assert not missing, (
                f"Pack {pack.name!r}: YARA rules missing from pack.yaml: {missing}"
            )
