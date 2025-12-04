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

"""Risk assessment module for A2A Scanner.

This module provides risk assessment capabilities for A2A Scanner results,
calculating overall risk levels, threat scores, and comprehensive security
posture evaluation based on detected vulnerabilities and threat patterns.
"""

from typing import Dict, Any


class RiskAssessor:
    """Assesses overall risk level from scan findings."""

    def assess_risk(self, stats: Dict) -> Dict[str, Any]:
        """Assess overall risk level from statistics.

        Args:
            stats: Statistics dictionary from StatisticsCalculator

        Returns:
            Risk assessment dictionary
        """
        high_count = stats["severity_counts"]["HIGH"]
        medium_count = stats["severity_counts"]["MEDIUM"]
        total = stats["total_findings"]

        if high_count >= 3:
            risk_level = "CRITICAL"
            risk_emoji = "[!]"
            risk_message = (
                "Multiple high-severity threats detected. Immediate action required."
            )
        elif high_count >= 1:
            risk_level = "HIGH"
            risk_emoji = "[!]"
            risk_message = (
                "High-severity threats detected. Review and remediate promptly."
            )
        elif medium_count >= 3:
            risk_level = "MEDIUM"
            risk_emoji = "[*]"
            risk_message = (
                "Multiple medium-severity threats detected. Review recommended."
            )
        elif total > 0:
            risk_level = "LOW"
            risk_emoji = "[i]"
            risk_message = (
                "Low-severity threats detected. Monitor and review as needed."
            )
        else:
            risk_level = "SAFE"
            risk_emoji = "[OK]"
            risk_message = "No threats detected. System appears secure."

        return {
            "level": risk_level,
            "emoji": risk_emoji,
            "message": risk_message,
            "score": self.calculate_risk_score(stats),
        }

    def calculate_risk_score(self, stats: Dict) -> int:
        """Calculate numerical risk score (0-100).

        Args:
            stats: Statistics dictionary

        Returns:
            Risk score from 0-100
        """
        high_count = stats["severity_counts"]["HIGH"]
        medium_count = stats["severity_counts"]["MEDIUM"]
        low_count = stats["severity_counts"]["LOW"]

        # Weighted score
        score = (high_count * 30) + (medium_count * 15) + (low_count * 5)

        # Cap at 100
        return min(score, 100)
