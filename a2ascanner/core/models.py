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

"""Data models module for A2A Scanner.

This module defines core data models for the A2A Scanner, including scan results,
security findings, and data structures used throughout the A2A protocol security
analysis system. Threat taxonomy is managed by the threats.py module.
"""

from typing import List, Optional, Dict, Any


class ScanResult:
    """Represents the result of scanning an A2A component.

    Attributes:
        target_name: Name of the scanned target (agent, server, etc.)
        target_type: Type of target (agent_card, sse_stream, registry, etc.)
        status: Scan status (completed, failed, partial)
        analyzers: List of analyzers used
        findings: List of security findings
        metadata: Additional metadata about the scan
    """

    def __init__(
        self,
        target_name: str,
        target_type: str,
        status: str = "completed",
        analyzers: Optional[List[str]] = None,
        findings: Optional[List[Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a scan result.

        Args:
            target_name: Name of the scanned target
            target_type: Type of target
            status: Scan status
            analyzers: List of analyzers used
            findings: List of security findings
            metadata: Additional metadata
        """
        self.target_name = target_name
        self.target_type = target_type
        self.status = status
        self.analyzers = analyzers or []
        self.findings = findings or []
        self.metadata = metadata or {}

    def has_findings(self) -> bool:
        """Check if scan has any findings.

        Returns:
            True if findings exist
        """
        return len(self.findings) > 0

    def get_high_severity_findings(self) -> List[Any]:
        """Get only high severity findings.

        Returns:
            List of high severity findings
        """
        return [f for f in self.findings if f.severity == "HIGH"]

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary format.

        Returns:
            Dictionary representation of the scan result
        """
        return {
            "target_name": self.target_name,
            "target_type": self.target_type,
            "status": self.status,
            "analyzers": self.analyzers,
            "findings": [
                f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings
            ],
            "metadata": self.metadata,
            "total_findings": len(self.findings),
            "high_severity_count": len(self.get_high_severity_findings()),
        }

    def __str__(self) -> str:
        return (
            f"ScanResult(target={self.target_name}, "
            f"type={self.target_type}, "
            f"findings={len(self.findings)}, "
            f"status={self.status})"
        )
