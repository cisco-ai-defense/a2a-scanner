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

"""Spec Analyzer module for A2A Scanner.

This module contains the specification compliance analyzer for validating A2A
agent cards and implementations against the A2A protocol specification.
Based on validation principles from https://github.com/a2aproject/a2a-inspector
"""

import re
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from .base import BaseAnalyzer, SecurityFinding
from ...utils.logging_config import get_logger

logger = get_logger(__name__)


class SpecComplianceAnalyzer(BaseAnalyzer):
    """Validates A2A protocol specification compliance."""

    def __init__(self, config: Optional[Any] = None):
        """Initialize spec compliance analyzer.

        Args:
            config: Configuration object (optional)
        """
        super().__init__("SpecCompliance")
        self.config = config
        self.spec_version = "1.0"
        logger.info("Spec compliance analyzer initialized")

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze agent card for spec compliance.

        Args:
            content: JSON string of agent card
            context: Optional context (not used)

        Returns:
            List of security findings
        """
        findings = []

        try:
            # Parse JSON content
            card_data = json.loads(content)

            # Validate agent card data
            findings.extend(self._check_required_fields(card_data))
            findings.extend(self._check_field_formats(card_data))
            findings.extend(self._check_url(card_data))
            findings.extend(self._check_capabilities(card_data))
            findings.extend(self._check_skills(card_data))
            findings.extend(self._check_modes(card_data))

        except json.JSONDecodeError as e:
            findings.append(
                SecurityFinding(
                    severity="HIGH",
                    summary=f"Invalid JSON format: {str(e)}",
                    threat_name="JSON PARSE ERROR",
                    analyzer="Spec",
                    details={"error": str(e)},
                )
            )
        except Exception as e:
            logger.error(f"Spec analysis error: {e}")
            findings.append(
                SecurityFinding(
                    severity="MEDIUM",
                    summary=f"Spec analysis error: {str(e)}",
                    threat_name="ANALYSIS ERROR",
                    analyzer="Spec",
                    details={"error": str(e)},
                )
            )

        return findings

    def _check_required_fields(
        self, card_data: Dict[str, Any], location: str = "agent_card"
    ) -> List[SecurityFinding]:
        """Check that all required fields are present.

        Per A2A spec, required fields are:
        - name: Agent name
        - description: Agent description
        - url: Agent endpoint URL
        - version: Version string
        - skills: Array of skills (can be empty)

        Args:
            card_data: Agent card dictionary
            location: Location string for findings

        Returns:
            List of security findings
        """
        findings: List[SecurityFinding] = []
        required_fields = {
            "name": "Agent name",
            "description": "Agent description",
            "url": "Agent endpoint URL",
            "version": "Version string",
            "skills": "Skills array",
        }

        for field, description in required_fields.items():
            if field not in card_data or card_data[field] is None:
                findings.append(
                    SecurityFinding(
                        severity="HIGH",
                        summary=f"Missing required field: '{field}' ({description})",
                        threat_name="MISSING REQUIRED FIELD",
                        analyzer="Spec",
                        details={
                            "field": field,
                            "description": description,
                            "location": location,
                            "mitigation": f"Add '{field}' field to agent card",
                        },
                    )
                )
            elif field == "skills" and not isinstance(card_data[field], list):
                findings.append(
                    SecurityFinding(
                        severity="HIGH",
                        summary=f"Field 'skills' must be an array, got {type(card_data[field]).__name__}",
                        threat_name="INVALID FIELD TYPE",
                        analyzer="Spec",
                        details={
                            "field": field,
                            "expected_type": "array/list",
                            "actual_type": type(card_data[field]).__name__,
                            "location": location,
                        },
                    )
                )

        return findings

    def _check_field_formats(
        self, card_data: Dict[str, Any], location: str = "agent_card"
    ) -> List[SecurityFinding]:
        """Validate field formats.

        Args:
            card_data: Agent card dictionary
            location: Location string

        Returns:
            List of security findings
        """
        findings: List[SecurityFinding] = []

        # Name validation - should be meaningful
        if "name" in card_data:
            name = card_data["name"]
            if isinstance(name, str):
                if len(name) < 3:
                    findings.append(
                        SecurityFinding(
                            severity="MEDIUM",
                            summary="Agent name should be at least 3 characters",
                            threat_name="INVALID AGENT NAME",
                            analyzer="Spec",
                            details={"name_length": len(name), "location": location},
                        )
                    )
                if not name.strip():
                    findings.append(
                        SecurityFinding(
                            severity="HIGH",
                            summary="Agent name cannot be empty or whitespace only",
                            threat_name="EMPTY AGENT NAME",
                            analyzer="Spec",
                            details={"location": location},
                        )
                    )

        # Version format - should follow semantic versioning
        if "version" in card_data:
            version = card_data["version"]
            if isinstance(version, str):
                # Loose semver check
                if not re.match(r"^\d+\.\d+", version):
                    findings.append(
                        SecurityFinding(
                            severity="LOW",
                            summary="Version should follow semantic versioning (e.g., '1.0.0')",
                            threat_name="INVALID VERSION FORMAT",
                            analyzer="Spec",
                            details={"version": version, "location": location},
                        )
                    )

        # Description validation
        if "description" in card_data:
            description = card_data["description"]
            if isinstance(description, str):
                if len(description) < 10:
                    findings.append(
                        SecurityFinding(
                            severity="LOW",
                            summary="Agent description should be descriptive (at least 10 characters)",
                            threat_name="INSUFFICIENT DESCRIPTION",
                            analyzer="Spec",
                            details={
                                "description_length": len(description),
                                "location": location,
                            },
                        )
                    )

        return findings

    def _check_url(
        self, card_data: Dict[str, Any], location: str = "agent_card"
    ) -> List[SecurityFinding]:
        """Validate agent URL.

        Args:
            card_data: Agent card dictionary
            location: Location string

        Returns:
            List of security findings
        """
        findings: List[SecurityFinding] = []

        if "url" not in card_data:
            return findings

        url = card_data["url"]
        if not isinstance(url, str):
            findings.append(
                SecurityFinding(
                    severity="HIGH",
                    summary=f"Agent URL must be a string, got {type(url).__name__}",
                    threat_name="INVALID URL TYPE",
                    analyzer="Spec",
                    details={"actual_type": type(url).__name__, "location": location},
                )
            )
            return findings

        # URL format validation
        if not url.startswith(("http://", "https://")):
            findings.append(
                SecurityFinding(
                    severity="HIGH",
                    summary="Agent URL must start with http:// or https://",
                    threat_name="INVALID URL FORMAT",
                    analyzer="Spec",
                    details={"url": url, "location": location},
                )
            )

        # Parse URL to check validity
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                findings.append(
                    SecurityFinding(
                        severity="HIGH",
                        summary="Agent URL is malformed (missing host)",
                        threat_name="MALFORMED URL",
                        analyzer="Spec",
                        details={"url": url, "location": location},
                    )
                )
        except Exception as e:
            findings.append(
                SecurityFinding(
                    severity="HIGH",
                    summary="Agent URL cannot be parsed",
                    threat_name="INVALID URL",
                    analyzer="Spec",
                    details={"url": url, "error": str(e), "location": location},
                )
            )

        return findings

    def _check_capabilities(
        self, card_data: Dict[str, Any], location: str = "agent_card"
    ) -> List[SecurityFinding]:
        """Validate capabilities structure.

        Per A2A spec, capabilities is an optional object with boolean flags:
        - streaming: boolean
        - pushNotifications: boolean
        - stateTransitionHistory: boolean

        Args:
            card_data: Agent card dictionary
            location: Location string

        Returns:
            List of security findings
        """
        findings: List[SecurityFinding] = []

        if "capabilities" not in card_data:
            # Capabilities are optional
            return findings

        capabilities = card_data["capabilities"]

        # Check type
        if not isinstance(capabilities, dict):
            findings.append(
                SecurityFinding(
                    severity="MEDIUM",
                    summary=f"Capabilities must be an object/dict, got {type(capabilities).__name__}",
                    threat_name="INVALID CAPABILITIES TYPE",
                    analyzer="Spec",
                    details={
                        "actual_type": type(capabilities).__name__,
                        "field": "capabilities",
                        "location": location,
                    },
                )
            )
            return findings

        # Check known capability fields
        known_capabilities = [
            "streaming",
            "pushNotifications",
            "stateTransitionHistory",
        ]

        for cap_name, cap_value in capabilities.items():
            # Warn about unknown capabilities
            if cap_name not in known_capabilities:
                findings.append(
                    SecurityFinding(
                        severity="LOW",
                        summary=f"Unknown capability: '{cap_name}' (not in A2A spec)",
                        threat_name="UNKNOWN CAPABILITY",
                        analyzer="Spec",
                        details={
                            "capability": cap_name,
                            "known_capabilities": known_capabilities,
                            "location": location,
                        },
                    )
                )

            # Check value type (should be boolean)
            if not isinstance(cap_value, bool):
                findings.append(
                    SecurityFinding(
                        severity="MEDIUM",
                        summary=f"Capability '{cap_name}' must be boolean, got {type(cap_value).__name__}",
                        threat_name="INVALID CAPABILITY VALUE",
                        analyzer="Spec",
                        details={
                            "capability": cap_name,
                            "expected_type": "boolean",
                            "actual_type": type(cap_value).__name__,
                            "location": location,
                        },
                    )
                )

        return findings

    def _check_skills(
        self, card_data: Dict[str, Any], location: str = "agent_card"
    ) -> List[SecurityFinding]:
        """Validate skills structure.

        Per A2A spec, each skill must have:
        - id: Unique identifier
        - name: Human-readable name
        - description: What the skill does

        Optional fields:
        - tags: Array of strings
        - examples: Array of example inputs

        Args:
            card_data: Agent card dictionary
            location: Location string

        Returns:
            List of security findings
        """
        findings: List[SecurityFinding] = []

        if "skills" not in card_data:
            return findings

        skills = card_data["skills"]

        if not isinstance(skills, list):
            return findings  # Already caught in required fields check

        if len(skills) == 0:
            findings.append(
                SecurityFinding(
                    severity="MEDIUM",
                    summary="Agent has no skills defined (empty array)",
                    threat_name="NO SKILLS DEFINED",
                    analyzer="Spec",
                    details={"location": location},
                )
            )
            return findings

        # Track skill IDs for uniqueness
        skill_ids = set()

        for i, skill in enumerate(skills):
            if not isinstance(skill, dict):
                findings.append(
                    SecurityFinding(
                        severity="HIGH",
                        summary=f"Skill #{i+1} must be an object, got {type(skill).__name__}",
                        threat_name="INVALID SKILL TYPE",
                        analyzer="Spec",
                        details={"skill_index": i + 1, "location": location},
                    )
                )
                continue

            # Check required skill fields
            required_skill_fields = ["id", "name", "description"]
            for field in required_skill_fields:
                if field not in skill or not skill[field]:
                    findings.append(
                        SecurityFinding(
                            severity="HIGH",
                            summary=f"Skill #{i+1} missing required field: '{field}'",
                            threat_name="MISSING SKILL FIELD",
                            analyzer="Spec",
                            details={
                                "skill_index": i + 1,
                                "field": field,
                                "location": location,
                            },
                        )
                    )

            # Check skill ID uniqueness
            if "id" in skill:
                skill_id = skill["id"]
                if skill_id in skill_ids:
                    findings.append(
                        SecurityFinding(
                            severity="HIGH",
                            summary=f"Skill ID '{skill_id}' is used multiple times",
                            threat_name="DUPLICATE SKILL ID",
                            analyzer="Spec",
                            details={"skill_id": skill_id, "location": location},
                        )
                    )
                skill_ids.add(skill_id)

            # Validate optional fields if present
            if "tags" in skill and not isinstance(skill["tags"], list):
                findings.append(
                    SecurityFinding(
                        severity="LOW",
                        summary=f"Skill #{i+1} 'tags' must be an array",
                        threat_name="INVALID SKILL TAGS",
                        analyzer="Spec",
                        details={"skill_index": i + 1, "location": location},
                    )
                )

            if "examples" in skill and not isinstance(skill["examples"], list):
                findings.append(
                    SecurityFinding(
                        severity="LOW",
                        summary=f"Skill #{i+1} 'examples' must be an array",
                        threat_name="INVALID SKILL EXAMPLES",
                        analyzer="Spec",
                        details={"skill_index": i + 1, "location": location},
                    )
                )

        return findings

    def _check_modes(
        self, card_data: Dict[str, Any], location: str = "agent_card"
    ) -> List[SecurityFinding]:
        """Validate input/output modes.

        Optional fields that should be arrays if present:
        - defaultInputModes: Array of supported input MIME types
        - defaultOutputModes: Array of supported output MIME types

        Args:
            card_data: Agent card dictionary
            location: Location string

        Returns:
            List of security findings
        """
        findings: List[SecurityFinding] = []

        # Check defaultInputModes
        if "defaultInputModes" in card_data:
            input_modes = card_data["defaultInputModes"]
            if not isinstance(input_modes, list):
                findings.append(
                    SecurityFinding(
                        severity="MEDIUM",
                        summary=f"defaultInputModes must be an array, got {type(input_modes).__name__}",
                        threat_name="INVALID INPUT MODES TYPE",
                        analyzer="Spec",
                        details={"location": location},
                    )
                )
            elif len(input_modes) == 0:
                findings.append(
                    SecurityFinding(
                        severity="LOW",
                        summary="defaultInputModes is empty",
                        threat_name="EMPTY INPUT MODES",
                        analyzer="Spec",
                        details={"location": location},
                    )
                )

        # Check defaultOutputModes
        if "defaultOutputModes" in card_data:
            output_modes = card_data["defaultOutputModes"]
            if not isinstance(output_modes, list):
                findings.append(
                    SecurityFinding(
                        severity="MEDIUM",
                        summary=f"defaultOutputModes must be an array, got {type(output_modes).__name__}",
                        threat_name="INVALID OUTPUT MODES TYPE",
                        analyzer="Spec",
                        details={"location": location},
                    )
                )
            elif len(output_modes) == 0:
                findings.append(
                    SecurityFinding(
                        severity="LOW",
                        summary="defaultOutputModes is empty",
                        threat_name="EMPTY OUTPUT MODES",
                        analyzer="Spec",
                        details={"location": location},
                    )
                )

        return findings
