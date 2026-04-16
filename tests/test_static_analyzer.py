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

"""Tests for StaticAnalyzer (YAML signatures and YARA-X)."""

from __future__ import annotations

import pytest

from a2ascanner.core.analyzers.static import StaticAnalyzer
from a2ascanner.core.scan_policy import ScanPolicy


@pytest.fixture
def static_analyzer() -> StaticAnalyzer:
    policy = ScanPolicy.default()
    return StaticAnalyzer(policy=policy)


class TestStaticAnalyzer:
    @pytest.mark.asyncio
    async def test_detects_cloud_metadata(self, static_analyzer: StaticAnalyzer) -> None:
        content = '{"url": "http://169.254.169.254/latest/meta-data/"}'
        findings = await static_analyzer.analyze(content)
        assert any(
            "metadata" in f.summary.lower()
            or "data leakage" in f.threat_name.lower()
            or f.details.get("rule_id") == "cloud_metadata_access"
            for f in findings
        )

    @pytest.mark.asyncio
    async def test_empty_content(self, static_analyzer: StaticAnalyzer) -> None:
        findings = await static_analyzer.analyze("")
        assert findings == []

    @pytest.mark.asyncio
    async def test_disabled_rule_suppressed(self) -> None:
        policy = ScanPolicy()
        policy.disabled_rules = ["cloud_metadata_access"]
        analyzer = StaticAnalyzer(policy=policy)
        content = '{"url": "http://169.254.169.254/latest/meta-data/"}'
        findings = await analyzer.analyze(content)
        sig_findings = [f for f in findings if f.details.get("rule_id") == "cloud_metadata_access"]
        assert len(sig_findings) == 0
