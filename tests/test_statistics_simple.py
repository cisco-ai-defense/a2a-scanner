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

"""Simple tests for statistics and risk assessment."""

import pytest
from a2ascanner.core.results.statistics import StatisticsCalculator
from a2ascanner.core.results.risk_assessor import RiskAssessor


class TestStatisticsCalculator:
    """Test StatisticsCalculator class."""

    def test_calculator_can_be_initialized(self):
        """Test calculator initialization."""
        calc = StatisticsCalculator()
        assert calc is not None

    def test_calculate_returns_dict(self):
        """Test calculate returns dict."""
        calc = StatisticsCalculator()
        findings = [{"severity": "HIGH", "threat_name": "TEST", "scanner_category": "TEST", "analyzer": "Test"}]
        stats = calc.calculate(findings)
        assert isinstance(stats, dict)

    def test_calculate_with_empty_findings(self):
        """Test calculate with no findings."""
        calc = StatisticsCalculator()
        stats = calc.calculate([])
        assert isinstance(stats, dict)

    def test_group_by_category_works(self):
        """Test grouping by category."""
        calc = StatisticsCalculator()
        findings = [
            {"scanner_category": "CAT1"},
            {"scanner_category": "CAT1"},
            {"scanner_category": "CAT2"}
        ]
        grouped = calc.group_by_category(findings)
        assert isinstance(grouped, dict)
        assert "CAT1" in grouped


class TestRiskAssessor:
    """Test RiskAssessor class."""

    def test_risk_assessor_can_be_initialized(self):
        """Test risk assessor initialization."""
        assessor = RiskAssessor()
        assert assessor is not None

    def test_assess_risk_returns_dict(self):
        """Test assess risk returns dict."""
        assessor = RiskAssessor()
        stats = {
            "total_findings": 1,
            "severity_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0}
        }
        risk = assessor.assess_risk(stats)
        assert isinstance(risk, dict)

    def test_assess_risk_with_no_findings(self):
        """Test risk assessment with no findings."""
        assessor = RiskAssessor()
        stats = {
            "total_findings": 0,
            "severity_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }
        risk = assessor.assess_risk(stats)
        assert isinstance(risk, dict)
