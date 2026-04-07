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

"""Tests for ScanPolicy loading, presets, YAML I/O, and rule toggles."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from a2ascanner.core.scan_policy import ScanPolicy


class TestScanPolicyDefaults:
    def test_default_loads(self) -> None:
        policy = ScanPolicy.default()
        assert policy.policy_name in ("default", "balanced")

    def test_preset_strict(self) -> None:
        policy = ScanPolicy.from_preset("strict")
        assert policy.policy_name == "strict"

    def test_preset_permissive(self) -> None:
        policy = ScanPolicy.from_preset("permissive")
        assert policy.policy_name == "permissive"

    def test_preset_balanced_matches_default_file(self) -> None:
        balanced = ScanPolicy.from_preset("balanced")
        default = ScanPolicy.default()
        assert balanced.policy_name == default.policy_name

    def test_preset_names(self) -> None:
        names = ScanPolicy.preset_names()
        assert "strict" in names
        assert "balanced" in names
        assert "permissive" in names

    def test_unknown_preset_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown preset"):
            ScanPolicy.from_preset("not_a_real_preset")


class TestScanPolicyRoundTrip:
    def test_to_yaml_and_back(self, tmp_path: Path) -> None:
        policy = ScanPolicy.default()
        path = tmp_path / "test_policy.yaml"
        policy.to_yaml(path)
        loaded = ScanPolicy.from_yaml(path)
        assert loaded.policy_name == policy.policy_name
        assert loaded.policy_version == policy.policy_version
        assert loaded.disabled_rules == policy.disabled_rules
        assert loaded.severity_overrides == policy.severity_overrides
        assert loaded.analyzers.static == policy.analyzers.static
        assert loaded.analyzers.spec == policy.analyzers.spec
        assert loaded.llm_analysis.max_output_tokens == policy.llm_analysis.max_output_tokens

    def test_from_yaml_merges_nested_sections(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "policy_name": "custom",
                    "disabled_rules": ["a", "b"],
                    "severity_overrides": {"x": "LOW"},
                    "analyzers": {"static": False, "llm": True},
                }
            ),
            encoding="utf-8",
        )
        loaded = ScanPolicy.from_yaml(path)
        assert loaded.policy_name == "custom"
        assert loaded.disabled_rules == ["a", "b"]
        assert loaded.severity_overrides == {"x": "LOW"}
        assert loaded.analyzers.static is False
        assert loaded.analyzers.llm is True
        assert loaded.analyzers.spec is True


class TestScanPolicyRules:
    def test_is_rule_enabled(self) -> None:
        policy = ScanPolicy()
        policy.disabled_rules = ["test_rule"]
        assert policy.is_rule_enabled("test_rule") is False
        assert policy.is_rule_enabled("other_rule") is True

    def test_severity_override(self) -> None:
        policy = ScanPolicy()
        policy.severity_overrides = {"rule1": "LOW"}
        assert policy.get_effective_severity("rule1", "HIGH") == "LOW"
        assert policy.get_effective_severity("rule2", "HIGH") == "HIGH"
