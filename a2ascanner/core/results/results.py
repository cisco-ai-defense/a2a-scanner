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

"""A2A Scanner Results Processing

Comprehensive results processing system for A2A Scanner. Handles finding
normalization, enrichment, and formatting across multiple output modes
including summary views, detailed reports, table displays, and JSON exports.
"""

from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich import box

from ..threats import get_threat_info
from ..models import ScanResult
from .formatters import OutputMode, ResultFormatter, SEVERITY_SYMBOLS
from .statistics import StatisticsCalculator
from .risk_assessor import RiskAssessor
from ..analyzers.base import SecurityFinding


# Console for Rich output
_console = Console()


class ResultProcessor:
    """Centralized result processor for all analyzers."""

    def __init__(self, deduplicate: bool = True):
        """Initialize result processor.
        
        Args:
            deduplicate: If True, deduplicate findings from multiple analyzers
        """
        self.formatter = ResultFormatter()
        self.stats_calculator = StatisticsCalculator()
        self.risk_assessor = RiskAssessor()
        self.deduplicate = deduplicate

    def deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate findings from multiple analyzers.
        
        When multiple analyzers detect the same threat at the same location,
        merge them into a single finding that shows all analyzers that detected it.
        
        Args:
            findings: List of normalized findings
            
        Returns:
            Deduplicated list of findings with merged analyzer information
        """
        if not findings:
            return findings
        
        # Group findings by deduplication key
        finding_groups = {}
        
        for finding in findings:
            # Create a deduplication key based on:
            # - threat_category (normalized threat type)
            # - location (from details)
            threat_category = finding.get("scanner_category", "UNKNOWN")
            
            # Extract location from details
            details = finding.get("details", {})
            location = "unknown"
            
            if isinstance(details, dict):
                # Try different location fields
                if "field_location" in details:
                    location = details["field_location"]
                elif "field" in details:
                    location = details["field"]
                elif "field_name" in details:
                    location = details["field_name"]
                elif "matched_strings" in details and details["matched_strings"]:
                    # For YARA matches, use field_location from first match
                    first_match = details["matched_strings"][0]
                    if "field_location" in first_match:
                        location = first_match["field_location"]
            
            # Create deduplication key
            dedup_key = f"{threat_category}|{location}"
            
            if dedup_key not in finding_groups:
                finding_groups[dedup_key] = []
            finding_groups[dedup_key].append(finding)
        
        # Merge duplicates
        deduplicated = []
        
        for group in finding_groups.values():
            if len(group) == 1:
                # No duplicates, keep as is
                deduplicated.append(group[0])
            else:
                # Merge multiple findings
                merged = self._merge_findings(group)
                deduplicated.append(merged)
        
        return deduplicated
    
    def _merge_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple findings of the same threat into one.
        
        Args:
            findings: List of findings to merge (same threat, same location)
            
        Returns:
            Merged finding with combined information
        """
        # Use the first finding as base
        merged = findings[0].copy()
        
        # Collect all analyzers that detected this
        analyzers = [f.get("analyzer", "Unknown") for f in findings]
        unique_analyzers = sorted(set(analyzers))
        
        # Keep the original analyzer field (use first one for threat mapping compatibility)
        # but add additional fields to show all detections
        merged["analyzer"] = analyzers[0]  # Keep original for compatibility
        merged["detected_by_analyzers"] = unique_analyzers  # New field for all analyzers
        merged["detected_by_count"] = len(unique_analyzers)
        
        # Keep highest severity
        severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
        highest_severity = max(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "UNKNOWN"), 0)
        )
        merged["severity"] = highest_severity.get("severity", "UNKNOWN")
        
        # Combine summaries if they're different
        summaries = [f.get("summary", "") for f in findings]
        unique_summaries = []
        seen = set()
        for summary in summaries:
            # Normalize by removing extra whitespace
            normalized = " ".join(summary.split())
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique_summaries.append(summary)
        
        if len(unique_summaries) > 1:
            # Multiple different summaries, combine them
            merged["summary"] = " | ".join(unique_summaries)
        else:
            # Same summary from all analyzers
            merged["summary"] = unique_summaries[0] if unique_summaries else ""
        
        # Add note about multiple detections
        if len(unique_analyzers) > 1:
            if "details" not in merged or not isinstance(merged["details"], dict):
                merged["details"] = {}
            merged["details"]["deduplication_note"] = (
                f"Detected by {len(unique_analyzers)} analyzers: {', '.join(unique_analyzers)}"
            )
        
        return merged

    def normalize_finding(self, finding: SecurityFinding) -> Dict[str, Any]:
        """Normalize a finding to include threat taxonomy information.

        Args:
            finding: SecurityFinding object from an analyzer

        Returns:
            Normalized finding dictionary with taxonomy fields
        """
        # Get threat mapping information
        threat_info = get_threat_info(finding.analyzer, finding.threat_name)

        # Use scanner_category from threats.py as authoritative threat_category
        # This ensures consistency across all analyzers
        scanner_category = (
            threat_info.get("scanner_category", "UNKNOWN") if threat_info else "UNKNOWN"
        )

        # Build normalized finding with taxonomy
        normalized = {
            "threat_category": scanner_category,  # Use scanner_category from threats.py
            "threat_name": finding.threat_name,
            "severity": (
                threat_info.get("severity", finding.severity)
                if threat_info
                else finding.severity
            ),  # Use severity from threats.py if available
            "scanner_category": scanner_category,
            "aitech": threat_info.get("aitech", "") if threat_info else "",
            "aitech_name": threat_info.get("aitech_name", "") if threat_info else "",
            "aisubtech": threat_info.get("aisubtech", "") if threat_info else "",
            "aisubtech_name": (
                threat_info.get("aisubtech_name", "") if threat_info else ""
            ),
            "description": (
                threat_info.get("description", finding.summary)
                if threat_info
                else finding.summary
            ),
            "analyzer": finding.analyzer,
            "summary": finding.summary,
            "details": finding.details,
        }

        return normalized

    def process_findings(
        self, findings: List[SecurityFinding], mode: OutputMode = OutputMode.DETAILED
    ) -> Dict[str, Any]:
        """Process and normalize findings from all analyzers.

        Args:
            findings: List of security findings from analyzers
            mode: Output mode for formatting

        Returns:
            Processed results dictionary
        """
        # Normalize all findings
        normalized_findings = []
        for finding in findings:
            normalized = self.normalize_finding(finding)
            normalized_findings.append(normalized)

        # Deduplicate if enabled
        if self.deduplicate:
            normalized_findings = self.deduplicate_findings(normalized_findings)

        # Calculate statistics
        stats = self.stats_calculator.calculate(normalized_findings)

        # Group by category
        grouped = self.stats_calculator.group_by_category(normalized_findings)

        # Assess risk
        risk = self.risk_assessor.assess_risk(stats)

        # Format based on mode
        if mode == OutputMode.RAW:
            return self.formatter.format_raw(findings, stats)
        elif mode == OutputMode.SUMMARY:
            return self.formatter.format_summary(normalized_findings, stats)
        elif mode == OutputMode.DETAILED:
            return self.formatter.format_detailed(
                normalized_findings, stats, grouped, risk
            )
        elif mode == OutputMode.TABLE:
            return self.formatter.format_table(normalized_findings, stats)
        else:  # JSON
            return self.formatter.format_json(normalized_findings, stats, grouped)

    def format_for_display(
        self, scan_result: ScanResult, mode: OutputMode = OutputMode.DETAILED
    ) -> str:
        """Format scan result for console display with emojis and colors.

        Args:
            scan_result: The scan result to format
            mode: Display mode

        Returns:
            Formatted string for display
        """
        processed = self.process_findings(scan_result.findings, mode)

        if mode == OutputMode.SUMMARY:
            return self._display_summary(scan_result, processed)
        elif mode == OutputMode.TABLE:
            return self._display_table(scan_result, processed)
        elif mode == OutputMode.DETAILED:
            return self._display_detailed(scan_result, processed)
        else:
            return str(processed)

    def _display_summary(self, scan_result: ScanResult, processed: Dict) -> str:
        """Display summary format."""
        summary = processed["summary"]
        lines = [
            f"\n{'='*60}",
            "A2A Security Scan Summary",
            f"{'='*60}",
            f"Target: {scan_result.target_name} ({scan_result.target_type})",
            "",
            "Threat Overview:",
            f"  • Total Threats: {summary['total_threats']}",
            f"  • {SEVERITY_SYMBOLS['HIGH']} High Severity: {summary['high_severity']}",
            f"  • {SEVERITY_SYMBOLS['MEDIUM']} Medium Severity: {summary['medium_severity']}",
            f"  • {SEVERITY_SYMBOLS['LOW']} Low Severity: {summary['low_severity']}",
            f"  • Unique Threat Types: {summary['unique_threat_types']}",
            "",
            f"Threats Detected: {', '.join(summary['threat_ids']) if summary['threat_ids'] else 'None'}",
            f"{'='*60}\n",
        ]
        return "\n".join(lines)

    def _display_table(self, scan_result: ScanResult, processed: Dict) -> str:
        """Display table format."""
        stats = processed["statistics"]
        rows = processed["table_data"]

        lines = [
            f"\n{'='*100}",
            f"A2A Security Scan Results - {scan_result.target_name}",
            f"{'='*100}",
            "",
            f"Statistics: {stats['total_findings']} findings | "
            f"{SEVERITY_SYMBOLS['HIGH']} {stats['severity_counts']['HIGH']} HIGH | "
            f"{SEVERITY_SYMBOLS['MEDIUM']} {stats['severity_counts']['MEDIUM']} MEDIUM | "
            f"{SEVERITY_SYMBOLS['LOW']} {stats['severity_counts']['LOW']} LOW",
            "",
            f"{'─'*100}",
            f"{'Sev':<4} {'Category':<25} {'Severity':<10} {'Threat Name':<25} {'Analyzer':<12} {'Taxonomy':<20}",
            f"{'─'*100}",
        ]

        for row in rows:
            lines.append(
                f"{row['severity_emoji']:<4} "
                f"{row['scanner_category'][:23]:<25} "
                f"{row['severity']:<10} "
                f"{row['threat_name'][:23]:<25} "
                f"{row['analyzer']:<12} "
                f"{row['taxonomy'][:18]:<20}"
            )

        lines.append(f"{'='*100}\n")
        return "\n".join(lines)

    def _display_detailed(self, scan_result: ScanResult, processed: Dict) -> str:
        """Display detailed format grouped by analyzer with comprehensive statistics."""
        stats = processed["statistics"]
        risk = processed["risk_assessment"]

        # Group by analyzer instead of category
        grouped_by_analyzer = {}
        for finding in processed["all_findings"]:
            analyzer = finding.get("analyzer", "Unknown")
            if analyzer not in grouped_by_analyzer:
                grouped_by_analyzer[analyzer] = []
            grouped_by_analyzer[analyzer].append(finding)

        lines = [
            f"\n{'='*80}",
            "A2A Scanner - Detailed Results",
            f"{'='*80}",
            "",
            f"Scan Target: {scan_result.target_name} ({scan_result.target_type})",
            f"Status: {scan_result.status}",
            "",
        ]

        # Display findings grouped by analyzer
        for analyzer, findings in grouped_by_analyzer.items():
            # Calculate analyzer-level statistics
            threat_names = set(f.get("threat_name", "Unknown") for f in findings)
            severities = [f.get("severity", "UNKNOWN") for f in findings]
            highest_severity = (
                "HIGH"
                if "HIGH" in severities
                else "MEDIUM" if "MEDIUM" in severities else "LOW"
            )

            lines.extend(
                [
                    f"Analyzer: {analyzer}",
                    f"  • Severity: {highest_severity}",
                    f"  • Threat Names: {', '.join(sorted(threat_names))}",
                    f"  • Total Findings: {len(findings)}",
                    "",
                ]
            )

            # Show each finding
            for finding in findings:
                severity = finding.get("severity", "UNKNOWN")
                severity_symbol = SEVERITY_SYMBOLS.get(severity, "[UNKNOWN]")
                scanner_category = finding.get("scanner_category", "UNKNOWN")
                threat_name = finding.get("threat_name", "Unknown")

                # Build taxonomy line if available
                taxonomy_parts = []
                if finding.get("aitech") and finding.get("aitech_name"):
                    taxonomy_parts.append(
                        f"AITech: {finding['aitech']} - {finding['aitech_name']}"
                    )
                if finding.get("aisubtech") and finding.get("aisubtech_name"):
                    taxonomy_parts.append(
                        f"AISubtech: {finding['aisubtech']} - {finding['aisubtech_name']}"
                    )
                taxonomy_line = (
                    " | ".join(taxonomy_parts)
                    if taxonomy_parts
                    else "Not yet mapped to AI taxonomy"
                )

                lines.extend(
                    [
                        f"    {severity_symbol} [{scanner_category}] {threat_name}",
                        f"       Severity: {severity}",
                        f"       Taxonomy: {taxonomy_line}",
                        f"       Summary: {finding.get('summary', 'No summary')}",
                        "",
                    ]
                )

        lines.extend(
            [
                f"{'─'*80}",
                "Overall Statistics:",
                f"  • Total Findings: {stats['total_findings']}",
                f"  • {SEVERITY_SYMBOLS['HIGH']} High: {stats['severity_counts']['HIGH']} | "
                f"{SEVERITY_SYMBOLS['MEDIUM']} Medium: {stats['severity_counts']['MEDIUM']} | "
                f"{SEVERITY_SYMBOLS['LOW']} Low: {stats['severity_counts']['LOW']}",
                "",
                f"Risk Assessment: {risk['emoji']} {risk['level']} ({risk['score']}/100)",
                f"{risk['message']}",
                f"{'='*80}\n",
            ]
        )

        lines.append(f"\n{'='*80}\n")
        return "\n".join(lines)

    def display_rich_table(self, scan_result: ScanResult) -> None:
        """Display scan results in a Rich table format (default CLI view).

        Args:
            scan_result: The scan result to display
        """
        # Apply deduplication if enabled
        findings_to_display = scan_result.findings
        dedup_info = {}  # Track which findings were deduplicated
        
        if self.deduplicate and findings_to_display:
            # Normalize and deduplicate
            normalized = [self.normalize_finding(f) for f in findings_to_display]
            deduplicated = self.deduplicate_findings(normalized)
            
            # Convert back to SecurityFinding objects for display
            from ..analyzers.base import SecurityFinding
            findings_to_display = []
            for idx, norm_finding in enumerate(deduplicated):
                finding = SecurityFinding(
                    severity=norm_finding["severity"],
                    threat_name=norm_finding["threat_name"],
                    summary=norm_finding["summary"],
                    details=norm_finding["details"],
                    analyzer=norm_finding["analyzer"]
                )
                findings_to_display.append(finding)
                
                # Track deduplication info
                if norm_finding.get("detected_by_count", 0) > 1:
                    dedup_info[idx] = norm_finding.get("detected_by_analyzers", [])
        
        # Print header
        _console.print(f"\n[bold]Scan Results for: {scan_result.target_name}[/bold]")
        _console.print(f"Target Type: {scan_result.target_type}")
        _console.print(f"Status: {scan_result.status}")
        _console.print(f"Analyzers: {', '.join(scan_result.analyzers)}")
        _console.print(f"Total Findings: {len(findings_to_display)}", end="")
        
        # Show deduplication info
        if dedup_info:
            original_count = len(scan_result.findings)
            removed = original_count - len(findings_to_display)
            _console.print(f" [dim](deduplicated from {original_count}, removed {removed} duplicates)[/dim]\n")
        else:
            _console.print("\n")

        if not findings_to_display:
            _console.print(
                "[green]✓ No security threats or compliance issues detected[/green]\n"
            )
            return

        # Separate findings by type
        security_findings = []
        spec_findings = []

        for idx, finding in enumerate(findings_to_display):
            finding_dict = finding.to_dict()
            if finding_dict.get("analyzer") == "Spec":
                spec_findings.append((idx, finding))
            else:
                security_findings.append((idx, finding))

        # Display security findings if any
        if security_findings:
            self._display_security_table(security_findings, dedup_info)

        # Display spec compliance findings if any
        if spec_findings:
            self._display_spec_table(spec_findings, dedup_info)

    def _display_security_table(self, findings: List, dedup_info: Dict = None) -> None:
        """Display security findings table.

        Args:
            findings: List of tuples (idx, SecurityFinding) for security findings (non-Spec)
            dedup_info: Dictionary mapping finding index to list of analyzers that detected it
        """
        dedup_info = dedup_info or {}

        # Create security findings table with better row separation
        table = Table(
            title="[bold magenta]Security Findings[/bold magenta]",
            box=box.HEAVY_HEAD,
            show_header=True,
            header_style="bold cyan",
            row_styles=[
                "none",
                "bright_black on default",
            ],  # Alternating row styles for better readability
        )

        table.add_column("Analyzer", width=10)
        table.add_column("Location", width=20)
        table.add_column("Threat Name", width=16)
        table.add_column("AITech", width=18)
        table.add_column("AISubtech", width=18)
        table.add_column("Severity", style="bold", width=8)
        table.add_column("Summary", width=26)

        # Sort findings by severity (extract finding from tuple)
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_findings = sorted(
            findings, key=lambda t: severity_order.get(t[1].severity, 3)
        )

        for idx, finding in sorted_findings:
            # Color code severity
            if finding.severity == "HIGH":
                severity_style = "bold red"
            elif finding.severity == "MEDIUM":
                severity_style = "bold yellow"
            else:
                severity_style = "bold blue"

            # Convert finding to dict to get enriched taxonomy fields
            finding_dict = finding.to_dict()

            # Extract location/field information from details
            details = finding_dict.get("details", {})
            location = "-"

            if isinstance(details, dict):
                # For YARA findings - show field location if available
                if "matched_strings" in details and details["matched_strings"]:
                    first_match = details["matched_strings"][0]

                    # Prefer field_location if available
                    if "field_location" in first_match:
                        location = first_match["field_location"]
                    else:
                        # Fallback to parsing sample
                        sample = first_match.get("sample", "")
                        # Parse JSON-like field reference (e.g., "url": "http://" -> url)
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
                                # Show matched content
                                location = (
                                    sample[:18].strip()
                                    if len(sample) <= 18
                                    else sample[:15].strip() + "..."
                                )
                        else:
                            # Show matched content for non-field matches
                            location = (
                                sample[:18].strip()
                                if len(sample) <= 18
                                else sample[:15].strip() + "..."
                            )
                # For spec and heuristic findings - show field name (standardized)
                elif "field" in details:
                    location = details["field"]
                elif "field_name" in details:
                    location = details["field_name"]
                elif "matches" in details:
                    # Show first match location
                    matches = details.get("matches", [])
                    if matches and isinstance(matches, list):
                        location = f"pattern: {matches[0][:15]}..."

            # Build AITech display - show both ID and Name without truncation
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

            # Build AISubtech display - show both ID and Name without truncation
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

            # Build analyzer display - show all analyzers if deduplicated
            if idx in dedup_info:
                analyzer_display = ", ".join(dedup_info[idx])
            else:
                analyzer_display = finding_dict.get("analyzer", "Unknown")

            table.add_row(
                analyzer_display,
                location,
                finding.threat_name,
                aitech_display,
                aisubtech_display,
                f"[{severity_style}]{finding.severity}[/{severity_style}]",
                (
                    finding.summary[:75] + "..."
                    if len(finding.summary) > 75
                    else finding.summary
                ),
            )

        _console.print(table)
        _console.print()

    def _display_spec_table(self, findings: List, dedup_info: Dict = None) -> None:
        """Display specification compliance findings table.

        Args:
            findings: List of tuples (idx, SecurityFinding) for spec compliance findings
            dedup_info: Dictionary mapping finding index to list of analyzers that detected it
        """
        dedup_info = dedup_info or {}
        
        # Create spec compliance table with better row separation
        table = Table(
            title="[bold magenta]Specification Compliance Issues[/bold magenta]",
            box=box.HEAVY_HEAD,
            show_header=True,
            header_style="bold cyan",
            row_styles=[
                "none",
                "bright_black on default",
            ],  # Alternating row styles for better readability
        )

        table.add_column("Analyzer", width=10)
        table.add_column("Location", width=20)
        table.add_column("Issue", width=30)
        table.add_column("Severity", style="bold", width=8)
        table.add_column("Description", width=45)

        # Sort findings by severity (extract finding from tuple)
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_findings = sorted(
            findings, key=lambda t: severity_order.get(t[1].severity, 3)
        )

        for idx, finding in sorted_findings:
            # Color code severity
            if finding.severity == "HIGH":
                severity_style = "bold red"
            elif finding.severity == "MEDIUM":
                severity_style = "bold yellow"
            else:
                severity_style = "bold blue"

            # Convert finding to dict
            finding_dict = finding.to_dict()

            # Extract location
            details = finding_dict.get("details", {})
            location = "-"

            if isinstance(details, dict) and "field" in details:
                location = details["field"]

            # Build analyzer display - show all analyzers if deduplicated
            if idx in dedup_info:
                analyzer_display = ", ".join(dedup_info[idx])
            else:
                analyzer_display = finding_dict.get("analyzer", "Spec")

            table.add_row(
                analyzer_display,
                location,
                finding.threat_name,
                f"[{severity_style}]{finding.severity}[/{severity_style}]",
                (
                    finding.summary[:75] + "..."
                    if len(finding.summary) > 75
                    else finding.summary
                ),
            )

        _console.print(table)
        _console.print()


# Global result processor instance (with deduplication enabled by default)
RESULT_PROCESSOR = ResultProcessor(deduplicate=True)
