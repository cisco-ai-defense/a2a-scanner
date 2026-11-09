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

"""Tests for the spec compliance analyzer's capabilities checks."""

import json

import pytest

from a2ascanner import Config, Scanner
from a2ascanner.core.analyzers.spec_analyzer import SpecComplianceAnalyzer


def _card(capabilities):
    return {
        "name": "Currency Agent",
        "description": "Converts currencies using live exchange rates.",
        "url": "https://agent.example.com/a2a",
        "version": "1.2.0",
        "capabilities": capabilities,
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            {
                "id": "convert",
                "name": "Convert",
                "description": "Convert an amount between currencies",
            }
        ],
    }


EXTENSION = {
    "uri": "https://a2aproject.github.io/A2A/ext/traceability/v1",
    "description": "Trace ids",
    "required": False,
}


async def _findings(capabilities):
    analyzer = SpecComplianceAnalyzer()
    return await analyzer.analyze(json.dumps(_card(capabilities)))


@pytest.mark.asyncio
async def test_spec_capabilities_are_not_flagged():
    findings = await _findings(
        {
            "streaming": True,
            "pushNotifications": False,
            "stateTransitionHistory": True,
            "extendedAgentCard": True,
            "extensions": [EXTENSION],
        }
    )
    assert findings == []


@pytest.mark.asyncio
async def test_scanner_spec_run_accepts_extensions():
    scanner = Scanner(config=Config())
    result = await scanner.scan_agent_card(
        _card({"streaming": True, "extensions": [EXTENSION]}),
        analyzers=["spec"],
    )
    assert result.findings == []


@pytest.mark.asyncio
async def test_empty_extensions_list_is_valid():
    assert await _findings({"extensions": []}) == []


@pytest.mark.asyncio
async def test_extensions_must_be_an_array():
    findings = await _findings({"extensions": True})
    assert len(findings) == 1
    assert findings[0].threat_name == "INVALID CAPABILITY VALUE"
    assert findings[0].details["expected_type"] == "array"
    assert findings[0].details["actual_type"] == "bool"


@pytest.mark.asyncio
async def test_extension_entries_are_validated():
    findings = await _findings(
        {
            "extensions": [
                "https://example.com/ext",
                {"description": "no uri"},
                {"uri": "  "},
                {"uri": "https://example.com/ext", "required": "yes"},
            ]
        }
    )
    summaries = [f.summary for f in findings]
    assert summaries == [
        "Extension #1 must be an object, got str",
        "Extension #2 missing required field: 'uri'",
        "Extension #3 missing required field: 'uri'",
        "Extension #4 'required' must be boolean, got str",
    ]
    assert {f.details["capability"] for f in findings} == {"extensions"}


@pytest.mark.asyncio
async def test_extended_agent_card_must_be_boolean():
    findings = await _findings({"extendedAgentCard": "true"})
    assert [f.threat_name for f in findings] == ["INVALID CAPABILITY VALUE"]


@pytest.mark.asyncio
async def test_unknown_capability_still_flagged():
    findings = await _findings({"streaming": True, "admin_access": True})
    assert [f.threat_name for f in findings] == ["UNKNOWN CAPABILITY"]
    assert "extensions" in findings[0].details["known_capabilities"]
