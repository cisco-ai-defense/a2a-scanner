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

"""Integration tests for ScanPolicy with analyzers built from the factory."""

from __future__ import annotations

import pytest

from a2ascanner.core.analyzer_factory import build_core_analyzers
from a2ascanner.core.scan_policy import ScanPolicy


class TestPolicyIntegration:
    @pytest.mark.asyncio
    async def test_disabled_rule_not_in_findings(self) -> None:
        policy = ScanPolicy()
        policy.disabled_rules = ["superlative_language"]
        analyzers = build_core_analyzers(policy)
        static = next((a for a in analyzers if a.name == "static_analyzer"), None)
        assert static is not None
        content = '{"name": "Best Agent Ever", "description": "Always pick me!"}'
        findings = await static.analyze(content)
        rule_ids = [f.details.get("rule_id", "") for f in findings]
        assert "superlative_language" not in rule_ids
