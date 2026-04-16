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

"""YARA Analyzer module for A2A Scanner.

This module contains the YARA analyzer class for analyzing A2A agent cards
using YARA rules. Provides fast, deterministic pattern matching for detecting
threat patterns including agent card spoofing, tool poisoning, message injection,
and network security issues.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yara_x

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from .base import BaseAnalyzer, SecurityFinding


class YaraAnalyzer(BaseAnalyzer):
    """YARA-based analyzer for detecting A2A threats using pattern matching.

    Uses the ``yara-x`` library for rule compilation and scanning.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        """Initialize the YARA analyzer.

        Args:
            rules_dir: Optional custom path to YARA rules directory.
                      If None, uses default rules from package data.
        """
        super().__init__("Yara")

        if not YARA_AVAILABLE:
            raise ImportError(
                "yara-x is not installed. Install it with: pip install yara-x"
            )

        if rules_dir:
            self.rules_dir = Path(rules_dir)
        else:
            package_dir = Path(__file__).parent.parent.parent
            self.rules_dir = package_dir / "data" / "packs" / "core" / "yara"

        if not self.rules_dir.exists():
            raise FileNotFoundError(f"YARA rules directory not found: {self.rules_dir}")

        self.rules = self._compile_rules()
        self.logger.info(f"Loaded YARA rules from: {self.rules_dir}")

    def _compile_rules(self) -> yara_x.Rules:
        """Compile all YARA rules from the rules directory."""
        rule_files: list[Path] = []
        for ext in ("*.yara", "*.yar"):
            rule_files.extend(self.rules_dir.glob(ext))

        if not rule_files:
            raise ValueError(
                f"No YARA rule files found in {self.rules_dir}. "
                f"Expected files with .yara or .yar extension."
            )

        self.logger.debug(f"Compiling {len(rule_files)} YARA rule files")

        compiler = yara_x.Compiler()
        for rule_file in sorted(rule_files):
            source = rule_file.read_text(encoding="utf-8")
            compiler.add_source(source)

        return compiler.build()

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze content using YARA rules.

        Args:
            content: The content to analyze (agent card, message, etc.)
            context: Additional context about the content

        Returns:
            List of security findings from YARA rule matches.
        """
        context = context or {}
        findings = []

        try:
            data = content.encode("utf-8") if isinstance(content, str) else content
            results = self.rules.scan(data)

            for matching_rule in results.matching_rules:
                meta = {k: v for k, v in matching_rule.metadata}

                severity = meta.get("severity", "UNKNOWN")
                threat_name = meta.get("threat_name", matching_rule.identifier)
                description = meta.get(
                    "description",
                    f"YARA rule {matching_rule.identifier} matched",
                )

                details: Dict[str, Any] = {
                    "rule_name": matching_rule.identifier,
                    "matched_strings": [],
                }

                for pattern in matching_rule.patterns:
                    for match in pattern.matches:
                        sample = data[match.offset : match.offset + match.length]
                        try:
                            sample_str = sample.decode("utf-8", errors="ignore")[:100]
                        except Exception:
                            sample_str = str(sample)[:100]

                        string_info: Dict[str, Any] = {
                            "offset": match.offset,
                            "length": match.length,
                            "sample": sample_str,
                        }
                        field_location = self._find_field_location(content, sample_str)
                        if field_location:
                            string_info["field_location"] = field_location
                        details["matched_strings"].append(string_info)

                if context:
                    details["context"] = context

                finding = self.create_security_finding(
                    severity=severity,
                    summary=description,
                    threat_name=threat_name,
                    details=details,
                )
                findings.append(finding)

            self.logger.debug(
                f"YARA analysis complete: {len(results.matching_rules)} rules matched, "
                f"{len(findings)} findings generated"
            )

        except Exception as e:
            self.logger.error(f"YARA analysis error: {e}")
            raise

        return findings

    def _find_field_location(
        self, json_content: str, matched_text: str
    ) -> Optional[str]:
        """Try to determine which JSON field contains the matched text.

        Args:
            json_content: The full JSON content that was scanned
            matched_text: The text that was matched by YARA

        Returns:
            Field path like "description", "capabilities[0].description", etc., or None
        """
        try:
            import json

            data = json.loads(json_content)

            # Clean up matched text - YARA often captures JSON delimiters
            # Remove common JSON syntax characters from the end
            cleaned_text = matched_text.rstrip("\",'}]")
            # Also try without leading characters
            cleaned_text = cleaned_text.lstrip('"{[')

            def search_dict(obj, path=""):
                """Recursively search through JSON structure."""
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        current_path = f"{path}.{key}" if path else key
                        if isinstance(value, str):
                            # Try both original and cleaned text
                            if matched_text in value or cleaned_text in value:
                                return current_path
                        result = search_dict(value, current_path)
                        if result:
                            return result
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        current_path = f"{path}[{i}]"
                        if isinstance(item, str):
                            # Try both original and cleaned text
                            if matched_text in item or cleaned_text in item:
                                return current_path
                        result = search_dict(item, current_path)
                        if result:
                            return result
                return None

            return search_dict(data)
        except (json.JSONDecodeError, TypeError, KeyError):
            return None

    def get_rule_count(self) -> int:
        """Get the number of loaded YARA rules.

        Returns:
            Number of compiled rules.
        """
        # YARA doesn't provide a direct way to count rules
        # We count the rule files instead
        return len(list(self.rules_dir.glob("*.yara"))) + len(
            list(self.rules_dir.glob("*.yar"))
        )
