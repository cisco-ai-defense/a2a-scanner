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

"""Compile and scan with YARA-X rules from a directory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yara_x

from ...data import DATA_DIR

_DEFAULT_YARA_DIR = DATA_DIR / "packs" / "core" / "yara"


def _rule_metadata_dict(matching_rule: Any) -> dict[str, Any]:
    """Normalize YARA-X rule metadata to a string-keyed dict."""
    meta: dict[str, Any] = {}
    raw = getattr(matching_rule, "metadata", ())
    for item in raw:
        if hasattr(item, "identifier") and hasattr(item, "value"):
            meta[str(item.identifier)] = item.value
        elif isinstance(item, (tuple, list)) and len(item) == 2:
            meta[str(item[0])] = item[1]
    return meta


class YaraScanner:
    """Load ``.yara`` / ``.yar`` sources with ``yara_x``, scan buffers, return match dicts."""

    def __init__(self, rules_dir: str | Path | None = None) -> None:
        self.rules_dir = Path(rules_dir).resolve() if rules_dir else _DEFAULT_YARA_DIR
        self._rules: yara_x.Rules | None = None

    def compile_rules(self) -> yara_x.Rules:
        """Read all ``.yara`` / ``.yar`` files under ``rules_dir`` and compile them."""
        if not self.rules_dir.is_dir():
            raise FileNotFoundError(f"YARA rules directory not found: {self.rules_dir}")

        paths = sorted(self.rules_dir.glob("*.yara")) + sorted(self.rules_dir.glob("*.yar"))
        if not paths:
            raise ValueError(
                f"No YARA rule files found in {self.rules_dir}. Expected .yara or .yar files."
            )

        compiler = yara_x.Compiler()
        for path in paths:
            source_text = path.read_text(encoding="utf-8")
            compiler.add_source(source_text, origin=str(path))

        self._rules = compiler.build()
        return self._rules

    def scan(self, content: str) -> list[dict[str, Any]]:
        """Run compiled rules against ``content`` and return structured matches."""
        if self._rules is None:
            self.compile_rules()
        assert self._rules is not None

        data_bytes = content.encode("utf-8", errors="surrogateescape")
        results = self._rules.scan(data_bytes)

        out: list[dict[str, Any]] = []
        for matching_rule in results.matching_rules:
            rule_name = matching_rule.identifier
            meta = _rule_metadata_dict(matching_rule)
            severity = str(meta.get("severity", "UNKNOWN"))
            threat_name = str(meta.get("threat_name", rule_name))
            description = str(meta.get("description", f"YARA rule {rule_name} matched"))

            patterns_matched: list[dict[str, int]] = []
            for pattern in matching_rule.patterns:
                for match in pattern.matches:
                    patterns_matched.append({"offset": match.offset, "length": match.length})

            out.append(
                {
                    "severity": severity,
                    "threat_name": threat_name,
                    "description": description,
                    "matched_strings": patterns_matched,
                    "rule_name": rule_name,
                }
            )
        return out
