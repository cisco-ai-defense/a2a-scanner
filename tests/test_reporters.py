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

"""Tests for JSON, SARIF, and Markdown reporters."""

from __future__ import annotations

import json

import pytest

from a2ascanner.core.models import ScanResult
from a2ascanner.core.reporters import JSONReporter, MarkdownReporter, SARIFReporter


@pytest.fixture
def sample_result() -> ScanResult:
    return ScanResult(target_name="test-agent", target_type="agent_card")


class TestJSONReporter:
    def test_generates_valid_json(self, sample_result: ScanResult) -> None:
        reporter = JSONReporter()
        output = reporter.generate_report(sample_result)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)
        assert parsed["target_name"] == "test-agent"
        assert parsed["target_type"] == "agent_card"


class TestSARIFReporter:
    def test_generates_valid_sarif(self, sample_result: ScanResult) -> None:
        reporter = SARIFReporter()
        output = reporter.generate_report(sample_result)
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert "$schema" in parsed
        assert "runs" in parsed and len(parsed["runs"]) == 1


class TestMarkdownReporter:
    def test_generates_markdown(self, sample_result: ScanResult) -> None:
        reporter = MarkdownReporter()
        output = reporter.generate_report(sample_result)
        assert "# A2A Scanner Report" in output
        assert "test-agent" in output
