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

"""Heuristic Analyzer module for A2A Scanner.

This module contains the heuristic analyzer for detecting threats in A2A agent
cards using compiled regex patterns and logic rules. Detects suspicious URLs,
cloud metadata access attempts, command execution patterns, credential harvesting,
and other behavioral indicators of malicious activity.
"""

import re
import json
from typing import Any, Dict, List, Optional

from .base import BaseAnalyzer, SecurityFinding


class HeuristicAnalyzer(BaseAnalyzer):
    """Heuristic-based analyzer for detecting A2A threats using logic and rules.

    Uses regex patterns and heuristics to detect threats that may not
    be caught by YARA rules alone.
    """

    def __init__(self):
        """Initialize the heuristic analyzer."""
        super().__init__("Heuristic")

        # Compile regex patterns for performance
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all regex patterns for efficient matching."""
        # Agent Card Spoofing Patterns
        self.superlative_pattern = re.compile(
            r"\b(always|never|best|perfect|ultimate|superior|guaranteed|"
            r"100%|all tasks|everything|pick me|choose me)\b",
            re.IGNORECASE,
        )

        # Suspicious URL patterns
        self.suspicious_url_pattern = re.compile(
            r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|"
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{4,5}",
            re.IGNORECASE,
        )

        # Cloud metadata endpoints
        self.metadata_pattern = re.compile(
            r"(?:169\.254\.169\.254|metadata\.google\.internal|"
            r"metadata\.azure\.com)",
            re.IGNORECASE,
        )

        # Command injection patterns - TUNED: Word boundaries to avoid false positives
        # Only match actual function calls, not substrings like "executor" or "execute"
        self.command_pattern = re.compile(
            r"\b(?:eval|exec|system)\s*\(|"  # eval(, exec(, system(
            r"\bsubprocess\s*\.|"  # subprocess.
            r"\bpopen\s*\(|"  # popen(
            r"shell\s*=\s*True",  # shell=True
            re.IGNORECASE,
        )

        # Credential patterns - tuned to avoid false positives in source code
        # Only match actual credential assignments/usage, not function/variable names
        self.credential_pattern = re.compile(
            r"(?:password|api[_-]?key|secret|token|credential)\s*[:=]", re.IGNORECASE
        )

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze content using Python-based patterns.

        Args:
            content: The content to analyze
            context: Additional context about the content

        Returns:
            List of security findings.
        """
        # Handle None or empty content
        if content is None or not content:
            return []

        context = context or {}
        findings = []

        # Try to parse as JSON for structured analysis
        try:
            data = json.loads(content)
            findings.extend(await self._analyze_json(data, context))
        except json.JSONDecodeError:
            # Not JSON, analyze as plain text
            pass

        # Run text-based pattern analysis
        findings.extend(await self._analyze_text(content, context))

        return findings

    async def _analyze_json(
        self, data: Dict[str, Any], context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Analyze JSON-structured content.

        Args:
            data: Parsed JSON data
            context: Analysis context

        Returns:
            List of findings.
        """
        findings = []

        # Check for agent card structure
        if isinstance(data, dict):
            # Check for mass registration patterns
            if "id" in data:
                agent_id = str(data["id"])
                if re.match(r"(agent|bot|helper)-\d{3,}", agent_id):
                    findings.append(
                        self.create_security_finding(
                            severity="MEDIUM",
                            summary=f"Suspicious agent ID pattern detected: {agent_id}",
                            threat_name="DISCOVERY POISONING",
                            details={
                                "agent_id": agent_id,
                                "pattern": "sequential_numbering",
                                "field": "id",
                            },
                        )
                    )

            # Check for suspicious URLs and text patterns in each field
            for key, value in data.items():
                if isinstance(value, str):
                    findings.extend(await self._check_urls(value, key, context))
                    # Check text patterns in this specific field
                    findings.extend(
                        await self._check_text_patterns(value, key, context)
                    )
                elif isinstance(value, dict):
                    # Recursively check nested objects
                    nested_findings = await self._analyze_json(value, context)
                    # Update field paths for nested findings
                    for finding in nested_findings:
                        if hasattr(finding, "details") and isinstance(
                            finding.details, dict
                        ):
                            if "field" in finding.details:
                                finding.details["field"] = (
                                    f"{key}.{finding.details['field']}"
                                )
                    findings.extend(nested_findings)

            # Check for priority abuse
            if "priority" in data:
                priority = data["priority"]
                if isinstance(priority, (int, float)) and priority >= 999:
                    findings.append(
                        self.create_security_finding(
                            severity="MEDIUM",
                            summary=f"Abnormally high priority value: {priority}",
                            threat_name="ROUTING MANIPULATION",
                            details={"priority": priority, "field": "priority"},
                        )
                    )

        return findings

    async def _analyze_text(
        self, content: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Analyze plain text content (for non-JSON content only).

        Args:
            content: Text content to analyze
            context: Analysis context

        Returns:
            List of findings.
        """
        # For non-JSON content, we don't know field names, so we just mark as "content"
        return await self._check_text_patterns(content, "content", context)

    async def _check_text_patterns(
        self, text: str, field_name: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check text patterns in a specific field.

        Args:
            text: Text to analyze
            field_name: Name of the field being analyzed
            context: Analysis context

        Returns:
            List of findings.
        """
        findings = []

        # Check for superlative language
        superlative_matches = self.superlative_pattern.findall(text)
        if len(superlative_matches) >= 2:
            findings.append(
                self.create_security_finding(
                    severity="MEDIUM",
                    summary=f"Multiple superlative claims detected in {field_name}: {', '.join(set(superlative_matches[:3]))}",
                    threat_name="AGENT CARD SPOOFING",
                    details={
                        "matches": list(set(superlative_matches)),
                        "count": len(superlative_matches),
                        "field": field_name,
                    },
                )
            )

        # Check for cloud metadata endpoints
        metadata_matches = self.metadata_pattern.findall(text)
        if metadata_matches:
            findings.append(
                self.create_security_finding(
                    severity="HIGH",
                    summary=f"Cloud metadata endpoint access detected in {field_name}",
                    threat_name="CLOUD METADATA ACCESS",
                    details={"endpoints": metadata_matches, "field": field_name},
                )
            )

        # Check for command execution patterns
        command_matches = self.command_pattern.findall(text)
        if command_matches:
            findings.append(
                self.create_security_finding(
                    severity="HIGH",
                    summary=f"Command execution patterns detected in {field_name}: {', '.join(set(command_matches))}",
                    threat_name="CODE EXECUTION",
                    details={
                        "patterns": list(set(command_matches)),
                        "field": field_name,
                    },
                )
            )

        # Check for credential harvesting - but skip for source code files
        # Source code often references credentials in legitimate ways (import statements, function names, etc.)
        file_extension = context.get("file_extension", "")
        is_source_code = file_extension in [".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".c", ".cpp", ".h"]
        
        if not is_source_code:
            credential_matches = self.credential_pattern.findall(text)
            if len(credential_matches) >= 2:
                # Check if there are also input/prompt keywords
                if re.search(
                    r"\b(input|prompt|enter|provide|supply)\b", text, re.IGNORECASE
                ):
                    findings.append(
                        self.create_security_finding(
                            severity="HIGH",
                            summary=f"Potential credential harvesting detected in {field_name}",
                            threat_name="DATA EXFILTRATION",
                            details={
                                "credential_types": list(set(credential_matches)),
                                "field": field_name,
                            },
                        )
                    )

        return findings

    async def _check_urls(
        self, text: str, field_name: str, context: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check URLs in text for suspicious patterns.

        Args:
            text: Text containing potential URLs
            field_name: Name of the field being checked
            context: Analysis context

        Returns:
            List of findings.
        """
        findings = []

        # Find suspicious URLs
        suspicious_urls = self.suspicious_url_pattern.findall(text)
        if suspicious_urls:
            findings.append(
                self.create_security_finding(
                    severity="MEDIUM",
                    summary=f"Suspicious localhost/IP URLs detected in {field_name}",
                    threat_name="SUSPICIOUS AGENT ENDPOINT",
                    details={
                        "urls": suspicious_urls,
                        "field": field_name,
                    },
                )
            )

        # Check for HTTP (non-HTTPS) URLs
        http_pattern = re.compile(r"http://(?!localhost|127\.0\.0\.1)", re.IGNORECASE)
        http_urls = http_pattern.findall(text)
        if http_urls and field_name in ["url", "endpoint", "callback"]:
            findings.append(
                self.create_security_finding(
                    severity="MEDIUM",
                    summary=f"Insecure HTTP URL detected in {field_name}",
                    threat_name="INSECURE NETWORK ACCESS",
                    details={
                        "field": field_name,
                        "issue": "HTTP instead of HTTPS",
                    },
                )
            )

        return findings

    async def analyze_agent_card(self, card: Dict[str, Any]) -> List[SecurityFinding]:
        """Specialized analysis for agent cards.

        Args:
            card: Agent card data

        Returns:
            List of findings specific to agent cards.
        """
        findings = []

        # Check name similarity to common agents (typosquatting)
        if "name" in card:
            name = card["name"].lower()
            common_names = ["trusted", "official", "verified", "secure", "authentic"]
            for common in common_names:
                # Check for character substitutions
                if any(
                    c in name for c in ["0", "1", "3", "5"]
                ) and common in name.replace("0", "o").replace("1", "i").replace(
                    "3", "e"
                ).replace(
                    "5", "s"
                ):
                    findings.append(
                        self.create_security_finding(
                            severity="HIGH",
                            summary=f"Potential typosquatting detected in agent name: {card['name']}",
                            threat_name="AGENT CARD SPOOFING",
                            details={
                                "name": card["name"],
                                "suspicious_pattern": "character_substitution",
                                "field": "name",
                            },
                        )
                    )
                    break

        return findings
