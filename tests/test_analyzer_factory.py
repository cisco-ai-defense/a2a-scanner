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

"""Tests for centralized analyzer construction."""

from __future__ import annotations

from a2ascanner.core.analyzer_factory import build_analyzers, build_core_analyzers
from a2ascanner.core.scan_policy import ScanPolicy


class TestAnalyzerFactory:
    def test_build_core_default(self) -> None:
        policy = ScanPolicy.default()
        analyzers = build_core_analyzers(policy)
        assert len(analyzers) >= 1
        names = [a.name for a in analyzers]
        assert "static_analyzer" in names
        assert "SpecCompliance" in names

    def test_build_with_static_disabled(self) -> None:
        policy = ScanPolicy()
        policy.analyzers.static = False
        analyzers = build_core_analyzers(policy)
        names = [a.name for a in analyzers]
        assert "static_analyzer" not in names

    def test_build_with_spec_disabled(self) -> None:
        policy = ScanPolicy()
        policy.analyzers.spec = False
        analyzers = build_core_analyzers(policy)
        names = [a.name for a in analyzers]
        assert "SpecCompliance" not in names

    def test_build_analyzers_includes_endpoint_when_policy_endpoint(self) -> None:
        policy = ScanPolicy()
        policy.analyzers.endpoint = True
        policy.analyzers.llm = False
        analyzers = build_analyzers(policy, use_endpoint=False, use_llm=False)
        names = [a.name for a in analyzers]
        assert "endpoint" in names
