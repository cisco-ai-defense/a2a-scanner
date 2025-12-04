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

"""Base Analyzer module for A2A Scanner.

This module contains the abstract base analyzer interface, security finding
data structures, and common functionality shared across all analyzer
implementations for A2A protocol threat detection.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ...utils.logging_config import get_logger


class SecurityFinding:
    """Represents a single security finding from an analyzer.

    Attributes:
        severity (str): The severity level: "HIGH", "MEDIUM", or "LOW".
        summary (str): A summary description of the security finding.
        threat_name (str): Human-readable threat name.
        analyzer (str): The name of the analyzer that found the security finding.
        details (Optional[Dict[str, Any]]): Additional details about the security finding.
    """

    def __init__(
        self,
        severity: str,
        summary: str,
        threat_name: str,
        analyzer: str,
        details: Optional[Dict[str, Any]] = None,
        threat_category: str = "",  # Deprecated parameter for backwards compatibility
    ):
        """Initialize a security finding.

        Args:
            severity (str): The severity level ("HIGH", "MEDIUM", "LOW").
            summary (str): A summary description of the security finding.
            threat_name (str): Human-readable threat name.
            analyzer (str): The name of the analyzer that found the security finding.
            details (Optional[Dict[str, Any]]): Additional details about the security finding.
            threat_category (str): Deprecated - no longer used.
        """
        # Validate and normalize inputs
        self.severity = self._normalize_severity(
            severity, ["HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"], "UNKNOWN"
        )
        self.summary = summary
        self.threat_name = threat_name
        self.analyzer = analyzer
        self.details = details or {}
        # Note: threat_category is deprecated and no longer stored

    def _normalize_severity(
        self, level: str, valid_levels: List[str], default: str
    ) -> str:
        """Normalize a level string to uppercase and validate against allowed values.

        Args:
            level: The level to normalize.
            valid_levels: List of valid level values.
            default: Default value if level is invalid.

        Returns:
            Normalized and validated level string.
        """
        if not level:
            return default

        normalized = level.upper()
        return normalized if normalized in valid_levels else default

    @property
    def threat_category(self) -> str:
        """Get threat category (scanner_category) from taxonomy.
        
        This property provides backwards compatibility for code expecting threat_category.
        
        Returns:
            The scanner_category from threat taxonomy, or empty string if not found.
        """
        from ..threats import get_threat_info
        threat_info = get_threat_info(self.analyzer, self.threat_name)
        return threat_info.get("scanner_category", "") if threat_info else ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary format with taxonomy enrichment.

        Returns:
            Dictionary representation of the finding with taxonomy fields.
        """
        from ..threats import get_threat_info

        # Get threat taxonomy information
        threat_info = get_threat_info(self.analyzer, self.threat_name)

        if threat_info:
            # Use enriched data from threats.py
            return {
                "severity": threat_info.get("severity", self.severity),
                "summary": self.summary,
                "threat_name": self.threat_name,
                "scanner_category": threat_info.get("scanner_category"),
                "aitech": threat_info.get("aitech", ""),
                "aitech_name": threat_info.get("aitech_name", ""),
                "aisubtech": threat_info.get("aisubtech", ""),
                "aisubtech_name": threat_info.get("aisubtech_name", ""),
                "description": threat_info.get("description", self.summary),
                "analyzer": self.analyzer,
                "details": self.details,
            }
        else:
            # Fallback to raw finding data if not found in taxonomy
            return {
                "severity": self.severity,
                "summary": self.summary,
                "threat_name": self.threat_name,
                "scanner_category": None,
                "aitech": "",
                "aitech_name": "",
                "aisubtech": "",
                "aisubtech_name": "",
                "description": self.summary,
                "analyzer": self.analyzer,
                "details": self.details,
            }

    def __str__(self) -> str:
        return f"{self.severity}: {self.threat_name} - {self.summary} (analyzer: {self.analyzer})"


class BaseAnalyzer(ABC):
    """Base class for all analyzers.

    This abstract class defines the interface that all analyzers must implement
    and provides shared functionality for logging, validation, and error handling.
    """

    def __init__(self, name: str):
        """Initialize the base analyzer.

        Args:
            name: The name of the analyzer for logging and identification.
        """
        self.name = name
        self.logger = get_logger(f"{__name__}.{name}")

    def validate_content(self, content: str) -> None:
        """Validate that content is suitable for analysis.

        Args:
            content: The content to validate.

        Raises:
            ValueError: If content is invalid.
        """
        if not content or not content.strip():
            raise ValueError("Content cannot be empty or whitespace-only")

        if len(content) > 500000:  # 500KB limit
            self.logger.warning(
                f"Content is very large ({len(content)} chars), analysis may be slow"
            )

    def create_security_finding(
        self,
        severity: str,
        summary: str,
        threat_name: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityFinding:
        """Create a security finding with this analyzer's name and standardized format.

        Args:
            severity: The severity level ("HIGH", "MEDIUM", "LOW").
            summary: Brief description of the security finding.
            threat_name: Human-readable threat name.
            details: Additional details about the security finding.

        Returns:
            SecurityFinding: The created security finding instance.
        """
        return SecurityFinding(
            severity=severity,
            summary=summary,
            threat_name=threat_name,
            analyzer=self.name,
            details=details,
        )

    async def safe_analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Safely analyze content with validation and error handling.

        Args:
            content: The content to analyze.
            context: Additional context for the analysis.

        Returns:
            List of security findings found, empty list on error.
        """
        try:
            self.validate_content(content)
            findings = await self.analyze(content, context)
            self.logger.info(
                f"Analysis complete: found {len(findings)} potential threats"
            )
            return findings
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return []

    @abstractmethod
    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze the provided content and return a list of security findings.

        Args:
            content (str): The content to analyze.
            context (Optional[Dict[str, Any]]): Additional context for the analysis.

        Returns:
            List[SecurityFinding]: The security findings found during the analysis.
        """
        pass
