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

"""Rich table report generation (console-oriented text with ANSI markup)."""

from __future__ import annotations

import io
from typing import Dict, List, Tuple

from rich import box
from rich.console import Console
from rich.table import Table

from ..analyzers.base import SecurityFinding
from ..models import ScanResult
from ..results.results import ResultProcessor


class TableReporter:
    """Build the same Rich tables as ``ResultProcessor.display_rich_table``, as a string."""

    def __init__(self, deduplicate: bool = True, console_width: int = 120) -> None:
        self._processor = ResultProcessor(deduplicate=deduplicate)
        self._console_width = console_width

    def generate_report(self, data: ScanResult) -> str:
        """Capture Rich table output for *data* into a string."""
        buf = io.StringIO()
        console = Console(file=buf, width=self._console_width, force_terminal=True)

        findings_to_display: List[SecurityFinding] = list(data.findings)
        dedup_info: Dict[int, List[str]] = {}

        if self._processor.deduplicate and findings_to_display:
            normalized = [self._processor.normalize_finding(f) for f in findings_to_display]
            deduplicated = self._processor.deduplicate_findings(normalized)
            findings_to_display = []
            for idx, norm_finding in enumerate(deduplicated):
                finding = SecurityFinding(
                    severity=norm_finding["severity"],
                    threat_name=norm_finding["threat_name"],
                    summary=norm_finding["summary"],
                    details=norm_finding["details"],
                    analyzer=norm_finding["analyzer"],
                )
                findings_to_display.append(finding)
                if norm_finding.get("detected_by_count", 0) > 1:
                    dedup_info[idx] = norm_finding.get("detected_by_analyzers", [])

        console.print(f"\n[bold]Scan Results for: {data.target_name}[/bold]")
        console.print(f"Target Type: {data.target_type}")
        console.print(f"Status: {data.status}")
        console.print(f"Analyzers: {', '.join(data.analyzers)}")
        console.print(f"Total Findings: {len(findings_to_display)}", end="")

        if dedup_info:
            original_count = len(data.findings)
            removed = original_count - len(findings_to_display)
            console.print(
                f" [dim](deduplicated from {original_count}, removed {removed} duplicates)[/dim]\n"
            )
        else:
            console.print("\n")

        if not findings_to_display:
            console.print("[green]✓ No security threats or compliance issues detected[/green]\n")
            return buf.getvalue()

        security_findings: List[Tuple[int, SecurityFinding]] = []
        spec_findings: List[Tuple[int, SecurityFinding]] = []

        for idx, finding in enumerate(findings_to_display):
            finding_dict = finding.to_dict()
            if finding_dict.get("analyzer") == "Spec":
                spec_findings.append((idx, finding))
            else:
                security_findings.append((idx, finding))

        if security_findings:
            self._render_security_table(console, security_findings, dedup_info)
        if spec_findings:
            self._render_spec_table(console, spec_findings, dedup_info)

        return buf.getvalue()

    def save_report(self, data, output_path) -> None:
        """Generate report and write to *output_path*."""
        from pathlib import Path as _P

        _P(output_path).write_text(self.generate_report(data), encoding="utf-8")

    def _render_security_table(
        self,
        console: Console,
        findings: List[Tuple[int, SecurityFinding]],
        dedup_info: Dict[int, List[str]],
    ) -> None:
        table = Table(
            title="[bold magenta]Security Findings[/bold magenta]",
            box=box.HEAVY_HEAD,
            show_header=True,
            header_style="bold cyan",
            row_styles=["none", "bright_black on default"],
        )

        table.add_column("Analyzer", width=10)
        table.add_column("Location", width=20)
        table.add_column("Threat Name", width=16)
        table.add_column("AITech", width=18)
        table.add_column("AISubtech", width=18)
        table.add_column("Severity", style="bold", width=8)
        table.add_column("Summary", width=26)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            findings, key=lambda t: severity_order.get(t[1].severity, 4)
        )

        for idx, finding in sorted_findings:
            if finding.severity in ("CRITICAL", "HIGH"):
                severity_style = "bold red"
            elif finding.severity == "MEDIUM":
                severity_style = "bold yellow"
            else:
                severity_style = "bold blue"

            finding_dict = finding.to_dict()
            details = finding_dict.get("details", {})
            location = "-"

            if isinstance(details, dict):
                if "matched_strings" in details and details["matched_strings"]:
                    first_match = details["matched_strings"][0]
                    if "field_location" in first_match:
                        location = first_match["field_location"]
                    else:
                        sample = first_match.get("sample", "")
                        if (
                            '"' in sample
                            and ":" in sample
                            and sample.strip().startswith('"')
                        ):
                            field_match = (
                                sample.split('"')[1] if sample.count('"') >= 2 else None
                            )
                            if field_match:
                                location = f"field: {field_match}"
                            else:
                                location = (
                                    sample[:18].strip()
                                    if len(sample) <= 18
                                    else sample[:15].strip() + "..."
                                )
                        else:
                            location = (
                                sample[:18].strip()
                                if len(sample) <= 18
                                else sample[:15].strip() + "..."
                            )
                elif "field" in details:
                    location = details["field"]
                elif "field_name" in details:
                    location = details["field_name"]
                elif "matches" in details:
                    matches = details.get("matches", [])
                    if matches and isinstance(matches, list):
                        location = f"pattern: {matches[0][:15]}..."

            aitech_id = finding_dict.get("aitech", "")
            aitech_name = finding_dict.get("aitech_name", "")
            if aitech_id and aitech_name:
                aitech_display = f"{aitech_id}\n{aitech_name}"
            elif aitech_id:
                aitech_display = aitech_id
            elif aitech_name:
                aitech_display = aitech_name
            else:
                aitech_display = "-"

            aisubtech_id = finding_dict.get("aisubtech", "")
            aisubtech_name = finding_dict.get("aisubtech_name", "")
            if aisubtech_id and aisubtech_name:
                aisubtech_display = f"{aisubtech_id}\n{aisubtech_name}"
            elif aisubtech_id:
                aisubtech_display = aisubtech_id
            elif aisubtech_name:
                aisubtech_display = aisubtech_name
            else:
                aisubtech_display = "-"

            if idx in dedup_info:
                analyzer_display = ", ".join(dedup_info[idx])
            else:
                analyzer_display = finding_dict.get("analyzer", "Unknown")

            summary_text = finding.summary
            if len(summary_text) > 75:
                summary_text = summary_text[:75] + "..."

            table.add_row(
                analyzer_display,
                location,
                finding.threat_name,
                aitech_display,
                aisubtech_display,
                f"[{severity_style}]{finding.severity}[/{severity_style}]",
                summary_text,
            )

        console.print(table)
        console.print()

    def _render_spec_table(
        self,
        console: Console,
        findings: List[Tuple[int, SecurityFinding]],
        dedup_info: Dict[int, List[str]],
    ) -> None:
        table = Table(
            title="[bold magenta]Specification Compliance Issues[/bold magenta]",
            box=box.HEAVY_HEAD,
            show_header=True,
            header_style="bold cyan",
            row_styles=["none", "bright_black on default"],
        )

        table.add_column("Analyzer", width=10)
        table.add_column("Location", width=20)
        table.add_column("Issue", width=30)
        table.add_column("Severity", style="bold", width=8)
        table.add_column("Description", width=45)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            findings, key=lambda t: severity_order.get(t[1].severity, 4)
        )

        for idx, finding in sorted_findings:
            if finding.severity in ("CRITICAL", "HIGH"):
                severity_style = "bold red"
            elif finding.severity == "MEDIUM":
                severity_style = "bold yellow"
            else:
                severity_style = "bold blue"

            finding_dict = finding.to_dict()
            details = finding_dict.get("details", {})
            location = "-"
            if isinstance(details, dict) and "field" in details:
                location = details["field"]

            if idx in dedup_info:
                analyzer_display = ", ".join(dedup_info[idx])
            else:
                analyzer_display = finding_dict.get("analyzer", "Spec")

            summary_text = finding.summary
            if len(summary_text) > 75:
                summary_text = summary_text[:75] + "..."

            table.add_row(
                analyzer_display,
                location,
                finding.threat_name,
                f"[{severity_style}]{finding.severity}[/{severity_style}]",
                summary_text,
            )

        console.print(table)
        console.print()
