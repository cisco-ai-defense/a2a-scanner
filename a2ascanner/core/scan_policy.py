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

"""
Scan policy: org-customisable disabled rules, severity overrides, and analyzer toggles.

Usage:
    from a2ascanner.core.scan_policy import ScanPolicy

    policy = ScanPolicy.default()
    policy = ScanPolicy.from_yaml("my_policy.yaml")
    policy = ScanPolicy.from_preset("strict")
    policy.to_yaml("generated_policy.yaml")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_MAX_PATTERN_LENGTH = 1000


def _safe_compile(
    pattern: str,
    flags: int = 0,
    max_length: int = _MAX_PATTERN_LENGTH,
) -> re.Pattern[str] | None:
    """Compile *pattern* with length and validity checks; return ``None`` on failure."""
    if not pattern or len(pattern) > max_length:
        logger.warning("Rejected pattern (length %d, max %d)", len(pattern) if pattern else 0, max_length)
        return None
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        logger.warning("Invalid regex pattern %r: %s", pattern[:80], exc)
        return None


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_DEFAULT_POLICY_PATH = _DATA_DIR / "default_policy.yaml"

_PRESET_POLICIES: dict[str, Path] = {
    "strict": _DATA_DIR / "strict_policy.yaml",
    "balanced": _DEFAULT_POLICY_PATH,
    "permissive": _DATA_DIR / "permissive_policy.yaml",
}


@dataclass
class SeverityOverride:
    """Override the severity of a specific rule."""

    rule_id: str
    severity: str


@dataclass
class AnalyzerPolicy:
    """Controls which analyzers are enabled."""

    static: bool = True
    spec: bool = True
    endpoint: bool = True
    llm: bool = False


@dataclass
class LLMAnalysisPolicy:
    """LLM analysis configuration."""

    enabled: bool = False
    model: str | None = None
    max_output_tokens: int = 8192


@dataclass
class FindingOutputPolicy:
    """Controls finding output behavior."""

    dedupe_exact_findings: bool = True
    dedupe_same_issue_per_location: bool = True
    attach_policy_fingerprint: bool = True
    annotate_same_path_rule_cooccurrence: bool = True


@dataclass
class ScanPolicy:
    """Org-customisable scan policy."""

    policy_name: str = "default"
    policy_version: str = "1.0"
    description: str = ""

    disabled_rules: list[str] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)

    analyzers: AnalyzerPolicy = field(default_factory=AnalyzerPolicy)
    llm_analysis: LLMAnalysisPolicy = field(default_factory=LLMAnalysisPolicy)
    finding_output: FindingOutputPolicy = field(default_factory=FindingOutputPolicy)

    @classmethod
    def default(cls) -> ScanPolicy:
        """Load the built-in default policy."""
        if _DEFAULT_POLICY_PATH.exists():
            return cls.from_yaml(_DEFAULT_POLICY_PATH)
        return cls()

    @classmethod
    def from_preset(cls, name: str) -> ScanPolicy:
        """Load a named preset policy (strict, balanced, permissive)."""
        name = name.lower().strip()
        if name not in _PRESET_POLICIES:
            available = ", ".join(sorted(_PRESET_POLICIES))
            raise ValueError(f"Unknown preset '{name}'. Available: {available}")
        return cls.from_yaml(_PRESET_POLICIES[name])

    @classmethod
    def preset_names(cls) -> list[str]:
        """Return available preset names."""
        return list(_PRESET_POLICIES.keys())

    @classmethod
    def from_yaml(cls, path: str | Path) -> ScanPolicy:
        """Load policy from a YAML file, merged on top of defaults.

        Callers that accept user-supplied paths **must** validate and
        constrain them before calling this method (e.g. restrict to a
        known directory or an allowlist of preset names).
        """
        path = Path(path)
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> ScanPolicy:
        """Build a ScanPolicy from a parsed YAML dict."""
        policy = cls()
        policy.policy_name = data.get("policy_name", policy.policy_name)
        policy.policy_version = data.get("policy_version", policy.policy_version)
        policy.description = data.get("description", policy.description)
        policy.disabled_rules = data.get("disabled_rules", [])
        policy.severity_overrides = data.get("severity_overrides", {})

        if "analyzers" in data:
            a = data["analyzers"]
            policy.analyzers = AnalyzerPolicy(
                static=a.get("static", True),
                spec=a.get("spec", True),
                endpoint=a.get("endpoint", True),
                llm=a.get("llm", False),
            )

        if "llm_analysis" in data:
            la = data["llm_analysis"]
            policy.llm_analysis = LLMAnalysisPolicy(
                enabled=la.get("enabled", False),
                model=la.get("model"),
                max_output_tokens=la.get("max_output_tokens", 8192),
            )

        if "finding_output" in data:
            fo = data["finding_output"]
            policy.finding_output = FindingOutputPolicy(
                dedupe_exact_findings=fo.get("dedupe_exact_findings", True),
                dedupe_same_issue_per_location=fo.get("dedupe_same_issue_per_location", True),
                attach_policy_fingerprint=fo.get("attach_policy_fingerprint", True),
                annotate_same_path_rule_cooccurrence=fo.get(
                    "annotate_same_path_rule_cooccurrence", True
                ),
            )

        return policy

    def to_yaml(self, path: str | Path) -> None:
        """Dump the current policy to a YAML file."""
        data = {
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "description": self.description,
            "disabled_rules": self.disabled_rules,
            "severity_overrides": self.severity_overrides,
            "analyzers": {
                "static": self.analyzers.static,
                "spec": self.analyzers.spec,
                "endpoint": self.analyzers.endpoint,
                "llm": self.analyzers.llm,
            },
            "llm_analysis": {
                "enabled": self.llm_analysis.enabled,
                "model": self.llm_analysis.model,
                "max_output_tokens": self.llm_analysis.max_output_tokens,
            },
            "finding_output": {
                "dedupe_exact_findings": self.finding_output.dedupe_exact_findings,
                "dedupe_same_issue_per_location": self.finding_output.dedupe_same_issue_per_location,
                "attach_policy_fingerprint": self.finding_output.attach_policy_fingerprint,
                "annotate_same_path_rule_cooccurrence": self.finding_output.annotate_same_path_rule_cooccurrence,
            },
        }
        path = Path(path)
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled (not in disabled_rules)."""
        return rule_id not in self.disabled_rules

    def get_effective_severity(self, rule_id: str, default_severity: str) -> str:
        """Get the effective severity for a rule, considering overrides."""
        return self.severity_overrides.get(rule_id, default_severity)
