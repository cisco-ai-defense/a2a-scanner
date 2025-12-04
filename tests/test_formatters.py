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

"""Tests for result formatters."""

import pytest
from a2ascanner.core.results.formatters import (
    ResultFormatter,
    OutputMode,
    SEVERITY_SYMBOLS
)
from a2ascanner.core.analyzers.base import SecurityFinding


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        SecurityFinding(
            severity="HIGH",
            summary="Critical security issue found",
            threat_name="AGENT CARD SPOOFING",
            analyzer="Yara",
            details={"rule_name": "test_rule"}
        ),
        SecurityFinding(
            severity="MEDIUM",
            summary="Moderate security concern",
            threat_name="PROMPT INJECTION",
            analyzer="Heuristic",
            details={"pattern": "test_pattern"}
        ),
        SecurityFinding(
            severity="LOW",
            summary="Minor security note",
            threat_name="MISSING FIELD",
            analyzer="Spec",
            details={}
        )
    ]


@pytest.fixture
def stats():
    """Create sample statistics."""
    return {
        "total": 3,
        "total_findings": 3,
        "by_severity": {"HIGH": 1, "MEDIUM": 1, "LOW": 1},
        "severity_counts": {"HIGH": 1, "MEDIUM": 1, "LOW": 1},
        "by_analyzer": {"Yara": 1, "Heuristic": 1, "Spec": 1},
        "unique_threats": 3,
        "threat_ids": ["AGENT CARD SPOOFING", "PROMPT INJECTION", "MISSING FIELD"]
    }


class TestResultFormatter:
    """Test ResultFormatter class."""

    def test_formatter_initialization(self):
        """Test formatter can be initialized."""
        formatter = ResultFormatter()
        assert formatter is not None

    def test_format_raw(self, sample_findings, stats):
        """Test RAW format output."""
        formatter = ResultFormatter()
        result = formatter.format_raw(sample_findings, stats)
        
        assert "findings" in result
        assert "stats" in result
        assert len(result["findings"]) == 3
        assert result["stats"]["total"] == 3

    def test_format_summary(self, sample_findings, stats):
        """Test SUMMARY format output."""
        formatter = ResultFormatter()
        
        # Normalize findings to dict format
        normalized = [f.to_dict() for f in sample_findings]
        result = formatter.format_summary(normalized, stats)
        
        assert "summary" in result
        assert "top_threats" in result
        assert result["summary"]["total_threats"] == 3

    def test_format_json(self, sample_findings, stats):
        """Test JSON format output."""
        formatter = ResultFormatter()
        
        normalized = [f.to_dict() for f in sample_findings]
        result = formatter.format_json(normalized, stats, {})
        
        assert "findings" in result
        assert "stats" in result
        assert len(result["findings"]) == 3

    def test_format_table(self, sample_findings, stats):
        """Test TABLE format output."""
        formatter = ResultFormatter()
        
        normalized = [f.to_dict() for f in sample_findings]
        result = formatter.format_table(normalized, stats)
        
        assert isinstance(result, dict)

    def test_format_detailed(self, sample_findings, stats):
        """Test DETAILED format output."""
        formatter = ResultFormatter()
        
        normalized = [f.to_dict() for f in sample_findings]
        grouped = {"AGENT CARD SPOOFING": [normalized[0]]}
        risk = {"level": "HIGH", "score": 85}
        
        result = formatter.format_detailed(normalized, stats, grouped, risk)
        
        assert isinstance(result, dict)


class TestOutputMode:
    """Test OutputMode enum."""

    def test_output_mode_values(self):
        """Test all output modes are defined."""
        assert hasattr(OutputMode, "RAW")
        assert hasattr(OutputMode, "SUMMARY")
        assert hasattr(OutputMode, "DETAILED")
        assert hasattr(OutputMode, "TABLE")
        assert hasattr(OutputMode, "JSON")


class TestFormatterConstants:
    """Test formatter constants."""

    def test_severity_emojis_defined(self):
        """Test severity emojis are defined."""
        assert "HIGH" in SEVERITY_SYMBOLS
        assert "MEDIUM" in SEVERITY_SYMBOLS
        assert "LOW" in SEVERITY_SYMBOLS


class TestFormatOutput:
    """Test format output with different modes."""

    def test_format_with_no_findings(self):
        """Test formatting when no findings."""
        formatter = ResultFormatter()
        stats = {"total": 0, "by_severity": {}, "by_analyzer": {}}
        
        result = formatter.format_raw([], stats)
        assert result["findings"] == []
        assert result["stats"]["total"] == 0

    def test_format_with_single_finding(self):
        """Test formatting with single finding."""
        formatter = ResultFormatter()
        finding = SecurityFinding(
            severity="HIGH",
            summary="Test",
            threat_name="TEST",
            analyzer="Test",
            details={}
        )
        stats = {"total": 1, "by_severity": {"HIGH": 1}, "by_analyzer": {"Test": 1}}
        
        result = formatter.format_raw([finding], stats)
        assert len(result["findings"]) == 1

    def test_format_preserves_details(self, sample_findings):
        """Test that formatting preserves finding details."""
        formatter = ResultFormatter()
        stats = {"total": 3, "total_findings": 3, "by_severity": {}, "severity_counts": {}, "by_analyzer": {}, "unique_threats": 0, "threat_ids": []}
        
        result = formatter.format_raw(sample_findings, stats)
        
        # Check first finding has details
        assert "details" in str(result["findings"][0])
        assert result["findings"][0].get("analyzer") == "Yara"

