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

"""Self-contained HTML report with embedded dark-theme CSS."""

from __future__ import annotations

import html as html_module
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..models import ScanResult


_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "SAFE")

_CSS = """
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --border: #30363d;
  --text: #e6edf3;
  --muted: #8b949e;
  --accent: #58a6ff;
  --high: #f85149;
  --medium: #d29922;
  --low: #58a6ff;
  --note: #8b949e;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  padding: 2rem 1.5rem 3rem;
}
main { max-width: 960px; margin: 0 auto; }
h1 { font-size: 1.75rem; font-weight: 600; margin: 0 0 0.5rem; }
.meta { color: var(--muted); font-size: 0.9rem; margin-bottom: 2rem; }
.meta strong { color: var(--text); }
section { margin-bottom: 2.5rem; }
h2 { font-size: 1.2rem; border-bottom: 1px solid var(--border); padding-bottom: 0.35rem; margin: 0 0 1rem; }
.summary-grid { display: flex; flex-wrap: wrap; gap: 0.75rem; }
.badge {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.35rem 0.75rem;
  border-radius: 6px;
  font-size: 0.85rem;
  font-weight: 600;
  background: var(--surface);
  border: 1px solid var(--border);
}
.badge .n { font-variant-numeric: tabular-nums; opacity: 0.9; }
.badge.high { border-color: var(--high); color: var(--high); }
.badge.medium { border-color: var(--medium); color: var(--medium); }
.badge.low { border-color: var(--low); color: var(--low); }
.badge.other { border-color: var(--note); color: var(--note); }
details.finding {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 0.65rem;
  overflow: hidden;
}
details.finding summary {
  cursor: pointer;
  padding: 0.85rem 1rem;
  list-style: none;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-weight: 500;
}
details.finding summary::-webkit-details-marker { display: none; }
details.finding summary::before {
  content: "▸";
  color: var(--muted);
  font-size: 0.75rem;
  transition: transform 0.15s;
}
details.finding[open] summary::before { transform: rotate(90deg); }
.finding-body { padding: 0 1rem 1rem; border-top: 1px solid var(--border); }
.finding-body dl { margin: 0; display: grid; grid-template-columns: 8rem 1fr; gap: 0.35rem 1rem; font-size: 0.9rem; }
.finding-body dt { color: var(--muted); margin: 0; }
.finding-body dd { margin: 0; word-break: break-word; }
pre.details {
  margin: 0.75rem 0 0;
  padding: 0.75rem 1rem;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.78rem;
  overflow-x: auto;
  color: var(--muted);
}
.sev-group h3 { font-size: 1rem; margin: 1.25rem 0 0.65rem; color: var(--muted); font-weight: 600; }
footer { margin-top: 3rem; color: var(--muted); font-size: 0.8rem; text-align: center; }
"""


def _badge_class(sev: str) -> str:
    u = sev.upper()
    if u in ("HIGH", "CRITICAL"):
        return "high"
    if u == "MEDIUM":
        return "medium"
    if u == "LOW":
        return "low"
    return "other"


class HTMLReporter:
    """Single-file HTML report: dark theme, summary badges, expandable findings."""

    def generate_report(self, data: ScanResult) -> str:
        ts = data.metadata.get("timestamp") if data.metadata else None
        if not ts:
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        findings_dicts: List[Dict[str, Any]] = []
        for f in data.findings:
            findings_dicts.append(f.to_dict() if hasattr(f, "to_dict") else dict(f))

        counts: Dict[str, int] = {}
        for fd in findings_dicts:
            sev = str(fd.get("severity", "UNKNOWN")).upper()
            counts[sev] = counts.get(sev, 0) + 1

        summary_badges: List[str] = []
        for sev in _SEVERITY_ORDER:
            if sev in counts:
                cls = _badge_class(sev)
                summary_badges.append(
                    f'<span class="badge {cls}">{html_module.escape(sev)} '
                    f'<span class="n">{counts[sev]}</span></span>'
                )
        for sev, n in sorted(counts.items()):
            if sev not in _SEVERITY_ORDER:
                summary_badges.append(
                    f'<span class="badge other">{html_module.escape(sev)} '
                    f'<span class="n">{n}</span></span>'
                )

        by_severity: Dict[str, List[Dict[str, Any]]] = {}
        for fd in findings_dicts:
            sev = str(fd.get("severity", "UNKNOWN")).upper()
            by_severity.setdefault(sev, []).append(fd)

        ordered_keys = [s for s in _SEVERITY_ORDER if s in by_severity]
        ordered_keys.extend(sorted(k for k in by_severity if k not in _SEVERITY_ORDER))

        finding_blocks: List[str] = []
        detail_id = 0
        for sev in ordered_keys:
            group = by_severity[sev]
            finding_blocks.append(f'<div class="sev-group"><h3>{html_module.escape(sev)}</h3>')
            for fd in group:
                threat = str(fd.get("threat_name", "Finding"))
                summary = str(fd.get("summary", ""))
                analyzer = str(fd.get("analyzer", ""))
                details_json = json.dumps(fd.get("details", {}), indent=2, default=str)
                sid = f"finding-{detail_id}"
                detail_id += 1

                finding_blocks.append(f'<details class="finding" id="{sid}">')
                finding_blocks.append(
                    "<summary>"
                    f'<span class="badge {_badge_class(sev)}">{html_module.escape(sev)}</span>'
                    f"<span>{html_module.escape(threat)}</span>"
                    "</summary>"
                )
                finding_blocks.append('<div class="finding-body">')
                finding_blocks.append("<dl>")
                finding_blocks.append(
                    f"<dt>Summary</dt><dd>{html_module.escape(summary)}</dd>"
                )
                finding_blocks.append(
                    f"<dt>Analyzer</dt><dd>{html_module.escape(analyzer)}</dd>"
                )
                finding_blocks.append(
                    f"<dt>Threat</dt><dd>{html_module.escape(threat)}</dd>"
                )
                finding_blocks.append("</dl>")
                finding_blocks.append(
                    "<pre class=\"details\">"
                    f"{html_module.escape(details_json)}</pre>"
                )
                finding_blocks.append("</div></details>")
            finding_blocks.append("</div>")

        summary_html = (
            '<div class="summary-grid">' + "".join(summary_badges) + "</div>"
            if summary_badges
            else '<p class="meta">No findings.</p>'
        )

        parts = [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\';">',
            "<title>A2A Scanner Report</title>",
            "<style>",
            _CSS,
            "</style>",
            "</head>",
            "<body>",
            "<main>",
            "<h1>A2A Scanner Report</h1>",
            '<p class="meta">',
            f"<strong>Target</strong> {html_module.escape(data.target_name)} &nbsp;·&nbsp; ",
            f"<strong>Type</strong> {html_module.escape(data.target_type)} &nbsp;·&nbsp; ",
            f"<strong>Status</strong> {html_module.escape(data.status)} &nbsp;·&nbsp; ",
            f"<strong>Time</strong> {html_module.escape(str(ts))}",
            "</p>",
            "<section>",
            "<h2>Summary</h2>",
            summary_html,
            f'<p class="meta" style="margin-top:1rem"><strong>Total findings:</strong> {len(findings_dicts)}</p>',
            "</section>",
            "<section>",
            "<h2>Findings</h2>",
            ("".join(finding_blocks) if finding_blocks else '<p class="meta">No issues reported.</p>'),
            "</section>",
            "<footer>Generated by a2a-scanner · self-contained report (no external assets)</footer>",
            "</main>",
            "</body>",
            "</html>",
        ]
        return "\n".join(parts) + "\n"

    def save_report(self, data, output_path) -> None:
        """Generate report and write to *output_path*."""
        from pathlib import Path as _P

        _P(output_path).write_text(self.generate_report(data), encoding="utf-8")
