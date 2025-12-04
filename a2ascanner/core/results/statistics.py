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

"""Statistics calculator module for A2A Scanner.

This module provides statistical analysis of A2A Scanner results, aggregating
and calculating comprehensive metrics from security findings including threat
distribution, severity analysis, and trend identification.
"""

from typing import Dict, Any, List


class StatisticsCalculator:
    """Calculates statistics from scan findings."""

    def calculate(self, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate comprehensive statistics from findings.

        Args:
            findings: List of normalized findings

        Returns:
            Dictionary with statistics
        """
        total = len(findings)

        # Count by severity
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

        for finding in findings:
            severity = finding.get("severity", "UNKNOWN")
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Count by analyzer
        analyzer_counts = {}
        for finding in findings:
            analyzer = finding.get("analyzer", "Unknown")
            analyzer_counts[analyzer] = analyzer_counts.get(analyzer, 0) + 1

        # Count by scanner category
        category_counts = {}
        for finding in findings:
            category = finding.get("scanner_category", "UNKNOWN")
            category_counts[category] = category_counts.get(category, 0) + 1

        # Count by aitech taxonomy
        aitech_counts = {}
        for finding in findings:
            aitech = finding.get("aitech", "Not mapped")
            if aitech:  # Only count if aitech is present
                aitech_counts[aitech] = aitech_counts.get(aitech, 0) + 1

        # Unique threat categories
        threat_categories = set(f.get("threat_category", "UNKNOWN") for f in findings)

        return {
            "total_findings": total,
            "severity_counts": severity_counts,
            "analyzer_counts": analyzer_counts,
            "category_counts": category_counts,
            "aitech_counts": aitech_counts,
            "unique_threats": len(threat_categories),
            "threat_ids": sorted(list(threat_categories)),
        }

    def group_by_category(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by scanner category.

        Args:
            findings: List of normalized findings

        Returns:
            Dictionary mapping scanner categories to findings
        """
        grouped = {}
        for finding in findings:
            category = finding.get("scanner_category", "UNKNOWN")
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(finding)
        return grouped

    def group_by_analyzer(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by analyzer.

        Args:
            findings: List of normalized findings

        Returns:
            Dictionary mapping analyzer names to findings
        """
        grouped = {}
        for finding in findings:
            analyzer = finding.get("analyzer", "Unknown")
            if analyzer not in grouped:
                grouped[analyzer] = []
            grouped[analyzer].append(finding)
        return grouped
