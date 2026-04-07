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

"""Static analyzer: YAML regex signatures plus YARA-X rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseAnalyzer, SecurityFinding
from ..scan_policy import ScanPolicy


def _virtual_scan_path(context: Optional[Dict[str, Any]]) -> Path:
    """Resolve a path for signature ``file_types`` filtering."""
    ctx = context or {}
    for key in ("path", "file_path", "filepath"):
        raw = ctx.get(key)
        if raw:
            return Path(raw)
    ext = ctx.get("file_extension", ".txt")
    if isinstance(ext, str):
        ext = ext.strip().lower()
        if ext and not ext.startswith("."):
            ext = f".{ext}"
    else:
        ext = ".txt"
    return Path(f"<scan>{ext or '.txt'}")


class StaticAnalyzer(BaseAnalyzer):
    """Runs packaged YAML signature rules and YARA-X rules against content."""

    def __init__(
        self,
        *,
        custom_yara_rules_path: str | Path | None = None,
        policy: ScanPolicy | None = None,
        extra_rules_dirs: list[Path] | None = None,
    ) -> None:
        super().__init__("static_analyzer")
        self.policy = policy if policy is not None else ScanPolicy.default()

        from ..rules.patterns import RuleLoader

        self.rule_loader = RuleLoader(extra_rules_dirs=extra_rules_dirs)
        self.signature_rules = self.rule_loader.load_rules()

        from ..rules.yara_scanner import YaraScanner

        yara_path = custom_yara_rules_path or None
        self.yara_scanner = YaraScanner(rules_dir=yara_path)
        self.yara_scanner.compile_rules()

    async def analyze(
        self,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityFinding]:
        if content is None or not content:
            return []

        findings: List[SecurityFinding] = []
        scan_path = _virtual_scan_path(context)

        for rule in self.signature_rules:
            if self.policy and not self.policy.is_rule_enabled(rule.id):
                continue
            matches = rule.scan_content(content, scan_path)
            for match in matches:
                severity = rule.severity
                if self.policy:
                    severity = self.policy.get_effective_severity(rule.id, severity)
                threat = rule.category.upper().replace("_", " ")
                findings.append(
                    self.create_security_finding(
                        severity=severity,
                        summary=rule.description,
                        threat_name=threat,
                        details={"rule_id": rule.id, "match": match},
                    )
                )

        yara_matches = self.yara_scanner.scan(content)
        for match in yara_matches:
            bare_name = match["rule_name"]
            rule_id = f"YARA_{bare_name}"
            if self.policy and (
                not self.policy.is_rule_enabled(rule_id)
                or not self.policy.is_rule_enabled(bare_name)
            ):
                continue
            severity = match.get("severity", "MEDIUM")
            if self.policy:
                severity = self.policy.get_effective_severity(bare_name, severity)
                severity = self.policy.get_effective_severity(rule_id, severity)
            findings.append(
                self.create_security_finding(
                    severity=severity,
                    summary=match.get(
                        "description", f"YARA rule {match['rule_name']} matched"
                    ),
                    threat_name=match.get("threat_name", match["rule_name"]),
                    details={
                        "rule_name": match["rule_name"],
                        "matched_strings": match.get("matched_strings", []),
                    },
                )
            )

        return findings

    def get_name(self) -> str:
        return "static_analyzer"
