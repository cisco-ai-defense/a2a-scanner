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

"""YAML signature rules with compiled regex patterns and directory loading."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ...data import DATA_DIR

_DEFAULT_SIGNATURES_DIR = DATA_DIR / "packs" / "core" / "signatures"


def _compile_many(
    patterns: list[str] | None, flags: int = 0
) -> list[re.Pattern[str]]:
    out: list[re.Pattern[str]] = []
    for p in patterns or []:
        if not p:
            continue
        out.append(re.compile(p, flags))
    return out


def _normalize_file_types(file_types: list[str] | None) -> list[str]:
    if not file_types:
        return []
    norm: list[str] = []
    for ft in file_types:
        ft = (ft or "").strip().lower()
        if not ft:
            continue
        if not ft.startswith("."):
            ft = f".{ft}"
        norm.append(ft)
    return norm


def _path_matches_file_types(file_path: str | Path, file_types: list[str]) -> bool:
    if not file_types:
        return True
    suffix = Path(file_path).suffix.lower()
    return suffix in file_types


def _line_excluded(line: str, exclude_patterns: list[re.Pattern[str]]) -> bool:
    return any(p.search(line) for p in exclude_patterns)


def _content_excluded(content: str, exclude_patterns: list[re.Pattern[str]]) -> bool:
    return any(p.search(content) for p in exclude_patterns)


class SecurityRule:
    """A single regex-based security rule loaded from a signature dict."""

    def __init__(self, rule: dict[str, Any]) -> None:
        self.id: str = str(rule["id"])
        self.category: str = str(rule.get("category", ""))
        self.severity: str = str(rule.get("severity", "MEDIUM"))
        self.description: str = str(rule.get("description", ""))
        self.file_types: list[str] = _normalize_file_types(rule.get("file_types"))
        self.remediation: str = str(rule.get("remediation", ""))

        raw_patterns = rule.get("patterns") or []
        if isinstance(raw_patterns, str):
            raw_patterns = [raw_patterns]
        raw_excludes = rule.get("exclude_patterns") or []
        if isinstance(raw_excludes, str):
            raw_excludes = [raw_excludes]

        # Case-insensitive matching; DOTALL/MULTILINE baked in so multiline scans need no
        # per-call flags (compiled Pattern.search does not accept flags on Python 3.11+).
        self.patterns: list[re.Pattern[str]] = _compile_many(
            list(raw_patterns), flags=re.IGNORECASE | re.DOTALL | re.MULTILINE
        )
        self.exclude_patterns: list[re.Pattern[str]] = _compile_many(
            list(raw_excludes), flags=re.IGNORECASE
        )

    def scan_content(self, content: str, file_path: str | Path) -> list[dict[str, Any]]:
        """Run per-line and multiline regex scans; honor file type and exclude patterns."""
        if not self.patterns:
            return []
        if not _path_matches_file_types(file_path, self.file_types):
            return []

        matches: list[dict[str, Any]] = []
        seen_spans: set[tuple[int, int]] = set()

        for pat in self.patterns:
            # Per-line scan (no DOTALL; line boundaries are explicit). Spans are global in ``content``.
            line_index = 0
            offset = 0
            while offset < len(content):
                nl = content.find("\n", offset)
                line_end = len(content) if nl == -1 else nl
                raw_line = content[offset:line_end]
                line_no = line_index + 1
                line_body = raw_line.rstrip("\r")

                if not _line_excluded(line_body, self.exclude_patterns):
                    m = pat.search(line_body)
                    if m:
                        g_start = offset + m.start()
                        g_end = offset + m.end()
                        sk = (g_start, g_end)
                        if sk not in seen_spans:
                            seen_spans.add(sk)
                            matches.append(
                                {
                                    "rule_id": self.id,
                                    "file_path": str(file_path),
                                    "line": line_no,
                                    "multiline": False,
                                    "match": m.group(0),
                                    "span": (g_start, g_end),
                                }
                            )

                if nl == -1:
                    break
                offset = nl + 1
                line_index += 1

            # Multiline scan across full content.
            if _content_excluded(content, self.exclude_patterns):
                continue
            m = pat.search(content)
            if m:
                start, end = m.span()
                sk = (start, end)
                if sk not in seen_spans:
                    seen_spans.add(sk)
                    prefix = content[:start]
                    line_no = prefix.count("\n") + 1
                    matches.append(
                        {
                            "rule_id": self.id,
                            "file_path": str(file_path),
                            "line": line_no,
                            "multiline": True,
                            "match": m.group(0),
                            "span": (start, end),
                        }
                    )

        return matches


class RuleLoader:
    """Load ``SecurityRule`` instances from YAML signature files in directories."""

    def __init__(
        self,
        signatures_dirs: list[Path] | None = None,
        extra_rules_dirs: list[Path] | None = None,
    ) -> None:
        if signatures_dirs is not None:
            dirs = list(signatures_dirs)
        else:
            dirs = [_DEFAULT_SIGNATURES_DIR]
        dirs = [Path(d).resolve() for d in dirs]
        if extra_rules_dirs:
            dirs.extend(Path(d).resolve() for d in extra_rules_dirs)
        self.signatures_dirs: list[Path] = dirs

    @staticmethod
    def _extract_rule_list(data: Any) -> list[dict[str, Any]]:
        if data is None:
            return []
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            sigs = data.get("signatures")
            if isinstance(sigs, list):
                return [x for x in sigs if isinstance(x, dict)]
        return []

    @staticmethod
    def _load_yaml_file(path: Path) -> list[dict[str, Any]]:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        return RuleLoader._extract_rule_list(data)

    def load(self) -> list[SecurityRule]:
        """Load all rules from ``*.yml`` / ``*.yaml`` under configured directories."""
        rules: list[SecurityRule] = []
        for base in self.signatures_dirs:
            if not base.is_dir():
                continue
            for path in sorted(base.glob("*.yml")):
                rules.extend(SecurityRule(r) for r in self._load_yaml_file(path))
            for path in sorted(base.glob("*.yaml")):
                rules.extend(SecurityRule(r) for r in self._load_yaml_file(path))
        return rules

    def load_rules(self) -> list[SecurityRule]:
        """Alias for :meth:`load` (API compatibility)."""
        return self.load()
