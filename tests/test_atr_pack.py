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

"""Tests for the ATR (Agent Threat Rules) rule pack.

Verifies the pack loads cleanly, detects a malicious A2A agent card via genuine
ATR signatures, and produces zero ATR findings across a realistic benign
agent-card corpus (devops/CI, db-admin, customer-support, billing-reporter,
marketing/link, data-analytics). The corpus is deliberately written in the
natural, conversational language real agent cards use (for example "I will also
check", "change of plans", "payment successful", "status: failed; will retry")
so it genuinely exercises the rules that previously produced false positives.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from a2ascanner.core.analyzers.static import StaticAnalyzer
from a2ascanner.core.rule_registry import PackLoader
from a2ascanner.core.scan_policy import ScanPolicy
from a2ascanner.data import _PACKS_DIR, list_available_packs, resolve_rule_packs

ATR_PACK_DIR = _PACKS_DIR / "atr"
ATR_TEST_DIR = ATR_PACK_DIR / "tests"
MALICIOUS_CARD = ATR_TEST_DIR / "malicious_agent_card.json"
BENIGN_CARD = ATR_TEST_DIR / "benign_agent_card.json"
BENIGN_CORPUS_DIR = ATR_TEST_DIR / "benign_corpus"
BENIGN_CORPUS_CARDS = sorted(BENIGN_CORPUS_DIR.glob("*.json"))


def _atr_rule_ids(findings) -> list[str]:
    ids: list[str] = []
    for finding in findings:
        details = getattr(finding, "details", {}) or {}
        rule_id = details.get("rule_id", "")
        if isinstance(rule_id, str) and rule_id.startswith("ATR_2026"):
            ids.append(rule_id)
    return sorted(set(ids))


@pytest.fixture
def atr_analyzer() -> StaticAnalyzer:
    return StaticAnalyzer(
        policy=ScanPolicy.default(),
        extra_rules_dirs=resolve_rule_packs(["atr"]),
    )


class TestAtrPackStructure:
    def test_pack_manifest_loads(self) -> None:
        pack = PackLoader.load_pack(ATR_PACK_DIR)
        assert pack.name == "atr"
        assert len(pack.rules) > 0

    def test_pack_is_discoverable(self) -> None:
        assert "atr" in list_available_packs()

    def test_pack_resolves_to_signatures_dir(self) -> None:
        dirs = resolve_rule_packs(["atr"])
        assert len(dirs) == 1
        assert dirs[0].is_dir()
        assert dirs[0].name == "signatures"

    def test_fixtures_exist(self) -> None:
        assert MALICIOUS_CARD.is_file()
        assert BENIGN_CARD.is_file()

    def test_benign_corpus_exists(self) -> None:
        # The 0-FP gate is only meaningful if it runs against a non-trivial,
        # realistic benign corpus. Guard against the corpus being deleted or
        # silently shrunk to a single rigged card.
        assert BENIGN_CORPUS_DIR.is_dir()
        assert len(BENIGN_CORPUS_CARDS) >= 6


class TestAtrPackDetection:
    @pytest.mark.asyncio
    async def test_malicious_card_triggers_atr_rules(
        self, atr_analyzer: StaticAnalyzer
    ) -> None:
        content = MALICIOUS_CARD.read_text(encoding="utf-8")
        findings = await atr_analyzer.analyze(content, {"path": str(MALICIOUS_CARD)})
        atr_ids = _atr_rule_ids(findings)
        # The malicious card carries agent-identity spoofing, A2A message
        # injection, SSRF, and credential-forwarding payloads. These genuinely
        # anchored detections must keep firing after the false-positive purge.
        assert len(atr_ids) >= 5
        expected = {
            "ATR_2026_00117",  # agent identity spoofing
            "ATR_2026_00116",  # A2A message injection
            "ATR_2026_00001",  # direct prompt injection
            "ATR_2026_00013",  # SSRF (cloud metadata endpoint)
            "ATR_2026_00030",  # cross-agent attack
            "ATR_2026_00074",  # cross-agent privilege escalation
            "ATR_2026_00114",  # OAuth / API token forwarding
        }
        missing = expected - set(atr_ids)
        assert not missing, f"malicious card no longer detected by: {sorted(missing)}"

    @pytest.mark.asyncio
    async def test_benign_card_zero_atr_findings(
        self, atr_analyzer: StaticAnalyzer
    ) -> None:
        content = BENIGN_CARD.read_text(encoding="utf-8")
        findings = await atr_analyzer.analyze(content, {"path": str(BENIGN_CARD)})
        atr_ids = _atr_rule_ids(findings)
        assert atr_ids == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "card", BENIGN_CORPUS_CARDS, ids=[c.stem for c in BENIGN_CORPUS_CARDS]
    )
    async def test_realistic_benign_card_zero_atr_findings(
        self, atr_analyzer: StaticAnalyzer, card: Path
    ) -> None:
        # Each realistic benign agent card must produce zero ATR findings.
        content = card.read_text(encoding="utf-8")
        findings = await atr_analyzer.analyze(content, {"path": str(card)})
        atr_ids = _atr_rule_ids(findings)
        assert atr_ids == [], f"{card.name} produced false positives: {atr_ids}"

    @pytest.mark.asyncio
    async def test_benign_corpus_zero_atr_findings_total(
        self, atr_analyzer: StaticAnalyzer
    ) -> None:
        # Aggregate 0-FP gate across the whole realistic benign corpus.
        total = 0
        per_card: dict[str, list[str]] = {}
        for card in BENIGN_CORPUS_CARDS:
            content = card.read_text(encoding="utf-8")
            findings = await atr_analyzer.analyze(content, {"path": str(card)})
            ids = _atr_rule_ids(findings)
            per_card[card.name] = ids
            total += len(ids)
        assert total == 0, f"ATR false positives across benign corpus: {per_card}"
