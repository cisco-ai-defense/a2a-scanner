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

"""Output formatters module for A2A Scanner.

This module provides multiple output formatting options for A2A Scanner results,
including raw output, summary views, detailed reports, table formats, and JSON
exports for flexible result presentation and integration.
"""

from enum import Enum
from typing import Dict, Any, List

# Severity symbol mapping for visual clarity
SEVERITY_SYMBOLS = {
    "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]",
    "UNKNOWN": "[UNKNOWN]",
}


class OutputMode(Enum):
    """Output display modes."""

    RAW = "raw"  # Raw findings as-is
    SUMMARY = "summary"  # Brief summary
    DETAILED = "detailed"  # Detailed with all info
    TABLE = "table"  # Table format
    JSON = "json"  # JSON export


class ResultFormatter:
    """Formats scan results for different output modes."""

    def format_summary(self, findings: List[Dict], stats: Dict) -> Dict[str, Any]:
        """Format findings as summary."""
        return {
            "summary": {
                "total_threats": stats["total_findings"],
                "high_severity": stats["severity_counts"]["HIGH"],
                "medium_severity": stats["severity_counts"]["MEDIUM"],
                "low_severity": stats["severity_counts"]["LOW"],
                "unique_threat_types": stats["unique_threats"],
                "threat_ids": stats["threat_ids"],
            },
            "top_threats": findings[:5] if findings else [],
        }

    def format_detailed(
        self, findings: List[Dict], stats: Dict, grouped: Dict, risk: Dict
    ) -> Dict[str, Any]:
        """Format findings with full details."""
        return {
            "statistics": stats,
            "findings_by_category": grouped,
            "all_findings": findings,
            "risk_assessment": risk,
        }

    def format_table(self, findings: List[Dict], stats: Dict) -> Dict[str, Any]:
        """Format findings for table display."""
        table_rows = []
        for finding in findings:
            # Build taxonomy label with both ID and name
            taxonomy_parts = []

            # Add aitech if available
            if finding.get("aitech"):
                aitech_label = finding.get("aitech")
                if finding.get("aitech_name"):
                    aitech_label = f"{aitech_label}: {finding.get('aitech_name')}"
                taxonomy_parts.append(aitech_label)

            # Add aisubtech if available (separated by | if aitech exists)
            if finding.get("aisubtech"):
                aisubtech_label = finding.get("aisubtech")
                if finding.get("aisubtech_name"):
                    aisubtech_label = (
                        f"{aisubtech_label}: {finding.get('aisubtech_name')}"
                    )
                taxonomy_parts.append(aisubtech_label)

            # Build final taxonomy string
            if taxonomy_parts:
                taxonomy = " | ".join(taxonomy_parts)
            else:
                taxonomy = "Not mapped"

            severity = finding.get("severity", "UNKNOWN")
            severity_symbol = SEVERITY_SYMBOLS.get(severity, "[UNKNOWN]")

            table_rows.append(
                {
                    "severity_emoji": severity_symbol,
                    "scanner_category": finding.get("scanner_category", "UNKNOWN"),
                    "severity": severity,
                    "threat_name": finding.get("threat_name", "Unknown Threat"),
                    "analyzer": finding.get("analyzer", "Unknown"),
                    "taxonomy": taxonomy,
                    "aitech": finding.get("aitech", ""),
                    "aitech_name": finding.get("aitech_name", ""),
                    "aisubtech": finding.get("aisubtech", ""),
                    "aisubtech_name": finding.get("aisubtech_name", ""),
                    "summary": (
                        finding.get("summary", "")[:60] + "..."
                        if len(finding.get("summary", "")) > 60
                        else finding.get("summary", "")
                    ),
                }
            )

        return {"statistics": stats, "table_data": table_rows}

    def format_raw(self, findings: List[Any], stats: Dict) -> Dict[str, Any]:
        """Format findings as raw data."""
        return {
            "findings": [f.__dict__ if hasattr(f, "__dict__") else f for f in findings],
            "stats": stats,
        }

    def format_json(
        self, findings: List[Dict], stats: Dict, grouped: Dict
    ) -> Dict[str, Any]:
        """Format findings as JSON."""
        return {"findings": findings, "stats": stats, "grouped": grouped}
