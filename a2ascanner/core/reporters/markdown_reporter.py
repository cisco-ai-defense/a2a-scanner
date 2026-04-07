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

"""Markdown report generation for scan results."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..models import ScanResult


_SEVERITY_ORDER = ("HIGH", "CRITICAL", "MEDIUM", "LOW", "UNKNOWN", "SAFE")


class MarkdownReporter:
    """Produce a Markdown document with summary and findings by severity."""

    def generate_report(self, data: ScanResult) -> str:
        lines: List[str] = []
        ts = data.metadata.get("timestamp") if data.metadata else None
        if not ts:
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines.append("# A2A Scanner Report")
        lines.append("")
        lines.append(f"**Target:** `{data.target_name}`  ")
        lines.append(f"**Target type:** `{data.target_type}`  ")
        lines.append(f"**Status:** `{data.status}`  ")
        lines.append(f"**Timestamp:** {ts}")
        lines.append("")

        findings_dicts: List[Dict[str, Any]] = []
        for f in data.findings:
            findings_dicts.append(f.to_dict() if hasattr(f, "to_dict") else dict(f))

        counts: Dict[str, int] = {}
        for fd in findings_dicts:
            sev = str(fd.get("severity", "UNKNOWN")).upper()
            counts[sev] = counts.get(sev, 0) + 1

        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in _SEVERITY_ORDER:
            if sev in counts:
                lines.append(f"| {sev} | {counts[sev]} |")
        for sev, n in sorted(counts.items()):
            if sev not in _SEVERITY_ORDER:
                lines.append(f"| {sev} | {n} |")
        if not counts:
            lines.append("| — | 0 |")
        lines.append("")
        lines.append(f"**Total findings:** {len(findings_dicts)}")
        lines.append("")

        by_severity: Dict[str, List[Dict[str, Any]]] = {}
        for fd in findings_dicts:
            sev = str(fd.get("severity", "UNKNOWN")).upper()
            by_severity.setdefault(sev, []).append(fd)

        lines.append("## Findings by severity")
        lines.append("")

        ordered_keys = [s for s in _SEVERITY_ORDER if s in by_severity]
        ordered_keys.extend(sorted(k for k in by_severity if k not in _SEVERITY_ORDER))

        for sev in ordered_keys:
            group = by_severity[sev]
            lines.append(f"### {sev}")
            lines.append("")
            for i, fd in enumerate(group, start=1):
                threat = fd.get("threat_name", "—")
                summary = fd.get("summary", "—")
                analyzer = fd.get("analyzer", "—")
                details = fd.get("details", {})
                lines.append(f"#### {i}. {threat}")
                lines.append("")
                lines.append(f"- **Severity:** {fd.get('severity', 'UNKNOWN')}")
                lines.append(f"- **Threat:** {threat}")
                lines.append(f"- **Summary:** {summary}")
                lines.append(f"- **Analyzer:** {analyzer}")
                lines.append("")
                lines.append("**Details:**")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(details, indent=2, default=str))
                lines.append("```")
                lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def save_report(self, data, output_path) -> None:
        """Generate report and write to *output_path*."""
        from pathlib import Path as _P

        _P(output_path).write_text(self.generate_report(data), encoding="utf-8")
