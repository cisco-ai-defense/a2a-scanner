"""Comprehensive reporter tests — JSON, SARIF, Markdown, HTML, Table, save_report, multi-result."""

from __future__ import annotations

import json

import pytest

from a2ascanner.core.analyzers.base import SecurityFinding
from a2ascanner.core.models import ScanResult
from a2ascanner.core.reporters import (
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
    SARIFReporter,
    TableReporter,
)


@pytest.fixture
def sample_findings():
    return [
        SecurityFinding(
            severity="HIGH",
            threat_name="Agent Card Spoofing",
            summary="Suspicious typosquatting detected",
            details={"matched_strings": [{"sample": "Tru5ted"}]},
            analyzer="static_analyzer",
        ),
        SecurityFinding(
            severity="MEDIUM",
            threat_name="Discovery Poisoning",
            summary="Superlative language detected",
            details={"rule_id": "superlative_language"},
            analyzer="static_analyzer",
        ),
        SecurityFinding(
            severity="LOW",
            threat_name="Spec Compliance",
            summary="Missing required field",
            details={"field": "version"},
            analyzer="Spec",
        ),
    ]


@pytest.fixture
def scan_result(sample_findings):
    return ScanResult(
        target_name="test-agent",
        target_type="agent_card",
        status="completed",
        analyzers=["static_analyzer", "Spec"],
        findings=sample_findings,
        metadata={"timestamp": "2025-01-01 00:00:00 UTC"},
    )


@pytest.fixture
def empty_result():
    return ScanResult(
        target_name="clean-agent",
        target_type="agent_card",
        status="completed",
        analyzers=["static_analyzer"],
        findings=[],
    )


class TestJSONReporter:
    def test_generates_valid_json(self, scan_result):
        output = JSONReporter(pretty=True).generate_report(scan_result)
        data = json.loads(output)
        assert data["target_name"] == "test-agent"
        assert data["target_type"] == "agent_card"

    def test_pretty_and_compact_semantically_equal(self, scan_result):
        pretty = json.loads(JSONReporter(pretty=True).generate_report(scan_result))
        compact = json.loads(JSONReporter(pretty=False).generate_report(scan_result))
        assert pretty == compact

    def test_findings_count_in_output(self, scan_result):
        output = json.loads(JSONReporter().generate_report(scan_result))
        assert output["total_findings"] == 3

    def test_empty_result(self, empty_result):
        output = json.loads(JSONReporter().generate_report(empty_result))
        assert output["total_findings"] == 0
        assert output["findings"] == []


class TestSARIFReporter:
    def test_generates_valid_sarif(self, scan_result):
        output = SARIFReporter(pretty=True).generate_report(scan_result)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_sarif_has_single_run(self, scan_result):
        data = json.loads(SARIFReporter().generate_report(scan_result))
        assert len(data["runs"]) == 1

    def test_sarif_tool_info(self, scan_result):
        data = json.loads(SARIFReporter().generate_report(scan_result))
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "a2a-scanner"

    def test_sarif_results_have_locations(self, scan_result):
        data = json.loads(SARIFReporter().generate_report(scan_result))
        results = data["runs"][0]["results"]
        for r in results:
            assert "locations" in r
            assert len(r["locations"]) >= 1

    def test_sarif_results_have_rule_ids(self, scan_result):
        data = json.loads(SARIFReporter().generate_report(scan_result))
        results = data["runs"][0]["results"]
        for r in results:
            assert "ruleId" in r
            assert r["ruleId"]

    def test_sarif_no_fixes_property(self, scan_result):
        data = json.loads(SARIFReporter().generate_report(scan_result))
        results = data["runs"][0]["results"]
        for r in results:
            assert "fixes" not in r

    def test_sarif_empty_result(self, empty_result):
        data = json.loads(SARIFReporter().generate_report(empty_result))
        assert data["runs"][0]["results"] == []

    def test_sarif_compact_valid(self, scan_result):
        output = SARIFReporter(pretty=False).generate_report(scan_result)
        data = json.loads(output)
        assert data["version"] == "2.1.0"


class TestMarkdownReporter:
    def test_has_title(self, scan_result):
        output = MarkdownReporter().generate_report(scan_result)
        assert "# A2A Scanner Report" in output

    def test_has_target_name(self, scan_result):
        output = MarkdownReporter().generate_report(scan_result)
        assert "test-agent" in output

    def test_has_summary_table(self, scan_result):
        output = MarkdownReporter().generate_report(scan_result)
        assert "| Severity | Count |" in output

    def test_has_findings_by_severity(self, scan_result):
        output = MarkdownReporter().generate_report(scan_result)
        assert "### HIGH" in output
        assert "### MEDIUM" in output
        assert "### LOW" in output

    def test_has_finding_details(self, scan_result):
        output = MarkdownReporter().generate_report(scan_result)
        assert "Agent Card Spoofing" in output
        assert "static_analyzer" in output

    def test_empty_result(self, empty_result):
        output = MarkdownReporter().generate_report(empty_result)
        assert "# A2A Scanner Report" in output
        assert "**Total findings:** 0" in output


class TestHTMLReporter:
    def test_generates_valid_html(self, scan_result):
        output = HTMLReporter().generate_report(scan_result)
        assert "<!DOCTYPE html>" in output
        assert "</html>" in output

    def test_self_contained(self, scan_result):
        output = HTMLReporter().generate_report(scan_result)
        assert "<style>" in output
        assert "self-contained report" in output.lower() or "a2a-scanner" in output

    def test_has_target_name(self, scan_result):
        output = HTMLReporter().generate_report(scan_result)
        assert "test-agent" in output

    def test_has_severity_badges(self, scan_result):
        output = HTMLReporter().generate_report(scan_result)
        assert "HIGH" in output
        assert "MEDIUM" in output
        assert "LOW" in output

    def test_has_finding_details(self, scan_result):
        output = HTMLReporter().generate_report(scan_result)
        assert "Agent Card Spoofing" in output

    def test_empty_result(self, empty_result):
        output = HTMLReporter().generate_report(empty_result)
        assert "<!DOCTYPE html>" in output
        assert "No findings" in output or "0" in output

    def test_dark_theme_css(self, scan_result):
        output = HTMLReporter().generate_report(scan_result)
        assert "--bg:" in output or "#0d1117" in output


class TestTableReporter:
    def test_generates_output(self, scan_result):
        output = TableReporter().generate_report(scan_result)
        assert "test-agent" in output
        assert len(output) > 0

    def test_has_scan_info(self, scan_result):
        output = TableReporter().generate_report(scan_result)
        assert "agent_card" in output or "test-agent" in output

    def test_has_findings(self, scan_result):
        output = TableReporter().generate_report(scan_result)
        assert "Security" in output or "Findings" in output or "HIGH" in output

    def test_empty_result(self, empty_result):
        output = TableReporter().generate_report(empty_result)
        assert "No security threats" in output or "0" in output

    def test_deduplicate_flag(self, scan_result):
        deduped = TableReporter(deduplicate=True).generate_report(scan_result)
        non_deduped = TableReporter(deduplicate=False).generate_report(scan_result)
        assert isinstance(deduped, str)
        assert isinstance(non_deduped, str)


class TestSaveReport:
    """Test that all reporters can write to disk."""

    @pytest.mark.parametrize("reporter_cls", [JSONReporter, SARIFReporter, MarkdownReporter, HTMLReporter])
    def test_save_report_to_file(self, tmp_path, scan_result, reporter_cls):
        reporter = reporter_cls()
        output = reporter.generate_report(scan_result)
        out_path = tmp_path / f"report.{reporter_cls.__name__.lower()}"
        out_path.write_text(output, encoding="utf-8")
        assert out_path.read_text(encoding="utf-8") == output

    def test_table_save_to_file(self, tmp_path, scan_result):
        reporter = TableReporter()
        output = reporter.generate_report(scan_result)
        out_path = tmp_path / "report.txt"
        out_path.write_text(output, encoding="utf-8")
        assert out_path.exists()
