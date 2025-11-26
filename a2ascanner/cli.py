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

#!/usr/bin/env python3
"""CLI module for A2A Scanner.

This module provides the command-line interface for the A2A Scanner with
comprehensive scanning capabilities for Agent-to-Agent protocol implementations,
including file scanning, directory scanning, registry analysis, and real-time
threat detection with multiple output formats and analyzer selection.
"""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console

from .config.config import Config
from .core.scanner import Scanner
from .core.results import RESULT_PROCESSOR
from .utils.logging_config import setup_logging


console = Console()


def print_banner():
    """Print scanner banner."""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           A2A Scanner v1.0.0                              ║
║     Agent-to-Agent Protocol Threat Detection              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def print_scan_result(result):
    """Print scan result in a formatted table (delegates to ResultProcessor).

    Args:
        result: ScanResult object
    """
    RESULT_PROCESSOR.display_rich_table(result)


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option(
    "--dev",
    is_flag=True,
    help="Enable development mode (allows localhost, skips SSL verification)",
)
@click.pass_context
def cli(ctx, debug, dev):
    """A2A Scanner - Detect threats in Agent-to-Agent protocols."""
    ctx.ensure_object(dict)

    # Setup logging
    # Use WARNING by default to reduce noise, DEBUG for --debug flag
    log_level = "DEBUG" if debug else "WARNING"
    setup_logging(log_level)

    # Store config in context
    config = Config()
    config.log_level = log_level
    config.dev_mode = dev

    ctx.obj["config"] = config

    # Show dev mode warning
    if dev:
        console.print("[yellow]WARNING: Development mode enabled:[/yellow]")
        console.print("   - Localhost URLs allowed")
        console.print("   - Private IP addresses allowed")
        console.print("   - SSL certificate verification disabled")
        console.print("   - HTTP connections allowed")
        console.print("[yellow]   DO NOT use in production![/yellow]\n")


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--analyzers",
    "-a",
    multiple=True,
    help="Specific analyzers to use (yara, pattern, llm)",
)
@click.option(
    "--output", "-o", type=click.Path(), help="Output file for results (JSON)"
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["summary", "table", "detailed", "json", "raw"]),
    default="table",
    help="Output format (default: table)",
)
@click.option(
    "--no-deduplicate",
    is_flag=True,
    help="Disable deduplication of findings from multiple analyzers",
)
@click.option(
    "--meta",
    "-m",
    is_flag=True,
    help="Run LLM meta-analysis to prune false positives and prioritize findings",
)
@click.option(
    "--meta-model",
    help="LLM model for meta-analysis (defaults to A2A_SCANNER_META_LLM_MODEL or primary LLM model)",
)
@click.option(
    "--meta-api-key",
    help="API key for meta-analysis LLM (defaults to A2A_SCANNER_META_LLM_API_KEY or primary API key)",
)
@click.pass_context
def scan_file(ctx, file_path, analyzers, output, format, no_deduplicate, meta, meta_model, meta_api_key):
    """Scan a file containing agent card or A2A protocol data.
    
    Use --meta to enable LLM meta-analysis which will:
    - Identify and filter false positives
    - Prioritize findings by actual risk
    - Provide specific recommendations and fixes
    
    Meta-analysis can use a different LLM than the primary analyzer:
    - Set A2A_SCANNER_META_LLM_MODEL for a different model
    - Set A2A_SCANNER_META_LLM_API_KEY for a different API key
    - Or use --meta-model and --meta-api-key flags
    """
    print_banner()

    config = ctx.obj["config"]

    async def run_scan():
        scanner = Scanner(config=config)

        console.print(f"[cyan]Scanning file: {file_path}[/cyan]\n")
        
        # Read file content for meta-analysis
        file_content = Path(file_path).read_text()

        # Run scan
        result = await scanner.scan_file(
            file_path=file_path,
            analyzers=list(analyzers) if analyzers else None,
        )

        meta_result = None
        
        # Run meta-analysis if requested
        if meta and result.has_findings():
            # Check for API key (meta-specific or primary)
            effective_api_key = meta_api_key or config.meta_llm_api_key
            if not effective_api_key:
                console.print(
                    "[yellow]⚠️  Meta-analysis requires LLM API key. "
                    "Set A2A_SCANNER_META_LLM_API_KEY or A2A_SCANNER_LLM_API_KEY environment variable.[/yellow]\n"
                )
            else:
                # Override config with CLI arguments if provided
                if meta_api_key:
                    config.meta_llm_api_key = meta_api_key
                if meta_model:
                    config.meta_llm_model = meta_model
                    
                console.print("\n[cyan]Running LLM meta-analysis...[/cyan]")
                if meta_model:
                    console.print(f"[dim]Using model: {meta_model}[/dim]")
                    
                try:
                    meta_result = await scanner.run_meta_analysis(result, file_content)
                    
                    # Apply meta-analysis to get filtered results
                    result = scanner.apply_meta_analysis(result, meta_result)
                    
                    # Display meta-analysis summary
                    summary = scanner.meta_analyzer.get_summary_report(meta_result)
                    console.print(f"\n[bold]Meta-Analysis Summary:[/bold]")
                    console.print(f"  Original findings: {summary['total_original_findings']}")
                    console.print(f"  Validated findings: {summary['validated_findings_count']}")
                    console.print(f"  False positives removed: {summary['false_positives_count']}")
                    console.print(f"  Recommendations: {summary['recommendations_count']}")
                    
                    risk = summary.get('overall_risk', {})
                    if risk:
                        risk_level = risk.get('risk_level', 'UNKNOWN')
                        risk_style = {
                            'HIGH': 'red bold',
                            'MEDIUM': 'yellow',
                            'LOW': 'green',
                            'SAFE': 'green bold',
                        }.get(risk_level, 'white')
                        console.print(f"  Overall Risk: [{risk_style}]{risk_level}[/{risk_style}]")
                    console.print()
                    
                except Exception as e:
                    console.print(f"[red]Meta-analysis failed: {e}[/red]\n")

        # Display results based on format
        if format == "json" or format == "raw":
            output_data = result.to_dict()
            if meta_result:
                output_data["meta_analysis"] = meta_result.to_dict()
            print(json.dumps(output_data, indent=2))
        elif format == "summary":
            from .core.results import RESULT_PROCESSOR, OutputMode

            output_text = RESULT_PROCESSOR.process_result(result, OutputMode.SUMMARY)
            print(output_text)
        elif format == "detailed":
            from .core.results import RESULT_PROCESSOR, OutputMode

            output_text = RESULT_PROCESSOR.process_result(result, OutputMode.DETAILED)
            print(output_text)
        else:
            print_scan_result(result)
            
        # Display recommendations if meta-analysis was run
        if meta_result and meta_result.recommendations:
            console.print("\n[bold cyan]Recommendations:[/bold cyan]")
            for i, rec in enumerate(meta_result.recommendations, 1):
                priority = rec.get('priority', 'MEDIUM')
                priority_style = {'HIGH': 'red bold', 'MEDIUM': 'yellow', 'LOW': 'green'}.get(priority, 'white')
                console.print(f"\n[{priority_style}]{i}. [{priority}][/{priority_style}] {rec.get('title', 'Recommendation')}")
                console.print(f"   {rec.get('description', '')}")
                if rec.get('fix'):
                    console.print(f"   [dim]Fix:[/dim]")
                    for line in rec.get('fix', '').split('\n')[:5]:
                        console.print(f"   [dim]{line}[/dim]")

        # Save to file if requested
        if output:
            output_path = Path(output)
            output_data = result.to_dict()
            if meta_result:
                output_data["meta_analysis"] = meta_result.to_dict()
            output_path.write_text(json.dumps(output_data, indent=2))
            console.print(f"\n[green]Results saved to: {output}[/green]\n")

        return result

    result = asyncio.run(run_scan())

    # Exit with error code if high severity findings
    if result.get_high_severity_findings():
        sys.exit(1)


@cli.command()
@click.argument("registry_url")
@click.option("--analyzers", "-a", multiple=True, help="Specific analyzers to use")
@click.option(
    "--output", "-o", type=click.Path(), help="Output file for results (JSON)"
)
@click.pass_context
def scan_registry(ctx, registry_url, analyzers, output):
    """Scan an agent registry for security threats."""
    print_banner()

    config = ctx.obj["config"]

    async def run_scan():
        scanner = Scanner(config=config)

        console.print(f"[cyan]Scanning registry: {registry_url}[/cyan]\n")

        # Run scan
        result = await scanner.scan_registry(
            registry_url=registry_url,
            analyzers=list(analyzers) if analyzers else None,
        )

        # Print results
        print_scan_result(result)

        # Save to file if requested
        if output:
            output_path = Path(output)
            output_path.write_text(json.dumps(result.to_dict(), indent=2))
            console.print(f"[green]Results saved to: {output}[/green]\n")

        return result

    result = asyncio.run(run_scan())

    # Exit with error code if high severity findings
    if result.get_high_severity_findings():
        sys.exit(1)


@cli.command()
@click.argument("endpoint_url")
@click.option("--timeout", "-t", default=30.0, help="Request timeout in seconds")
@click.option("--bearer-token", help="Bearer token for authentication")
@click.option(
    "--no-verify-ssl", is_flag=True, help="Disable SSL certificate verification"
)
@click.option(
    "--output", "-o", type=click.Path(), help="Output file for results (JSON)"
)
@click.pass_context
def scan_endpoint(ctx, endpoint_url, timeout, bearer_token, no_verify_ssl, output):
    """Scan a running A2A agent endpoint for security issues.

    Performs dynamic security testing of live agent endpoints including:
    - Security header checks
    - HTTPS enforcement
    - Agent card validation
    - Health endpoint detection

    Examples:
      a2a-scanner scan-endpoint https://agent.example.com
      a2a-scanner scan-endpoint https://agent.example.com --timeout 60
      a2a-scanner scan-endpoint https://agent.example.com --bearer-token YOUR_TOKEN
    """
    print_banner()

    config = ctx.obj["config"]

    async def run_scan():
        scanner = Scanner(config=config)

        console.print(f"[cyan]Scanning endpoint: {endpoint_url}[/cyan]\n")

        # Run endpoint scan
        result = await scanner.scan_endpoint(
            endpoint_url=endpoint_url,
            timeout=timeout,
            bearer_token=bearer_token,
            verify_ssl=not no_verify_ssl,
        )

        # Print results
        print_scan_result(result)

        # Save to file if requested
        if output:
            output_path = Path(output)
            output_path.write_text(json.dumps(result.to_dict(), indent=2))
            console.print(f"[green]Results saved to: {output}[/green]\n")

        return result

    result = asyncio.run(run_scan())

    # Exit with error code if high severity findings
    if result.get_high_severity_findings():
        sys.exit(1)


@cli.command()
@click.argument("card_file", type=click.Path(exists=True))
@click.option("--analyzers", "-a", multiple=True, help="Specific analyzers to use")
@click.option(
    "--output", "-o", type=click.Path(), help="Output file for results (JSON)"
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["summary", "table", "detailed", "json", "raw"]),
    default="table",
    help="Output format (default: table)",
)
@click.option(
    "--meta",
    "-m",
    is_flag=True,
    help="Run LLM meta-analysis to prune false positives and prioritize findings",
)
@click.option(
    "--meta-model",
    help="LLM model for meta-analysis (defaults to A2A_SCANNER_META_LLM_MODEL or primary LLM model)",
)
@click.option(
    "--meta-api-key",
    help="API key for meta-analysis LLM (defaults to A2A_SCANNER_META_LLM_API_KEY or primary API key)",
)
@click.pass_context
def scan_card(ctx, card_file, analyzers, output, format, meta, meta_model, meta_api_key):
    """Scan an agent card JSON file.
    
    Use --meta to enable LLM meta-analysis which will:
    - Identify and filter false positives
    - Prioritize findings by actual risk
    - Provide specific recommendations and fixes
    
    Meta-analysis can use a different LLM than the primary analyzer:
    - Set A2A_SCANNER_META_LLM_MODEL for a different model
    - Set A2A_SCANNER_META_LLM_API_KEY for a different API key
    - Or use --meta-model and --meta-api-key flags
    """
    print_banner()

    config = ctx.obj["config"]

    async def run_scan():
        scanner = Scanner(config=config)

        # Load agent card
        card_path = Path(card_file)
        card_data = json.loads(card_path.read_text())
        card_json = card_path.read_text()

        console.print(
            f"[cyan]Scanning agent card: {card_data.get('name', 'unknown')}[/cyan]\n"
        )

        # Run scan
        result = await scanner.scan_agent_card(
            card=card_data,
            analyzers=list(analyzers) if analyzers else None,
        )

        meta_result = None
        
        # Run meta-analysis if requested
        if meta and result.has_findings():
            # Check for API key (meta-specific or primary)
            effective_api_key = meta_api_key or config.meta_llm_api_key
            if not effective_api_key:
                console.print(
                    "[yellow]⚠️  Meta-analysis requires LLM API key. "
                    "Set A2A_SCANNER_META_LLM_API_KEY or A2A_SCANNER_LLM_API_KEY environment variable.[/yellow]\n"
                )
            else:
                # Override config with CLI arguments if provided
                if meta_api_key:
                    config.meta_llm_api_key = meta_api_key
                if meta_model:
                    config.meta_llm_model = meta_model
                    
                console.print("\n[cyan]Running LLM meta-analysis...[/cyan]")
                if meta_model:
                    console.print(f"[dim]Using model: {meta_model}[/dim]")
                    
                try:
                    meta_result = await scanner.run_meta_analysis(result, card_json)
                    
                    # Apply meta-analysis to get filtered results
                    result = scanner.apply_meta_analysis(result, meta_result)
                    
                    # Display meta-analysis summary
                    summary = scanner.meta_analyzer.get_summary_report(meta_result)
                    console.print(f"\n[bold]Meta-Analysis Summary:[/bold]")
                    console.print(f"  Original findings: {summary['total_original_findings']}")
                    console.print(f"  Validated findings: {summary['validated_findings_count']}")
                    console.print(f"  False positives removed: {summary['false_positives_count']}")
                    console.print(f"  Recommendations: {summary['recommendations_count']}")
                    
                    risk = summary.get('overall_risk', {})
                    if risk:
                        risk_level = risk.get('risk_level', 'UNKNOWN')
                        risk_style = {
                            'HIGH': 'red bold',
                            'MEDIUM': 'yellow',
                            'LOW': 'green',
                            'SAFE': 'green bold',
                        }.get(risk_level, 'white')
                        console.print(f"  Overall Risk: [{risk_style}]{risk_level}[/{risk_style}]")
                    console.print()
                    
                except Exception as e:
                    console.print(f"[red]Meta-analysis failed: {e}[/red]\n")

        # Display results based on format
        if format == "json" or format == "raw":
            # JSON/RAW format - print dict
            output_data = result.to_dict()
            if meta_result:
                output_data["meta_analysis"] = meta_result.to_dict()
            print(json.dumps(output_data, indent=2))
        elif format == "summary":
            # Summary format - using result processor
            from .core.results import RESULT_PROCESSOR, OutputMode

            output_text = RESULT_PROCESSOR.format_for_display(
                result, OutputMode.SUMMARY
            )
            print(output_text)
        elif format == "detailed":
            # Detailed format - using result processor
            from .core.results import RESULT_PROCESSOR, OutputMode

            output_text = RESULT_PROCESSOR.format_for_display(
                result, OutputMode.DETAILED
            )
            print(output_text)
        else:
            # Default table format
            print_scan_result(result)
            
        # Display recommendations if meta-analysis was run
        if meta_result and meta_result.recommendations:
            console.print("\n[bold cyan]Recommendations:[/bold cyan]")
            for i, rec in enumerate(meta_result.recommendations, 1):
                priority = rec.get('priority', 'MEDIUM')
                priority_style = {'HIGH': 'red bold', 'MEDIUM': 'yellow', 'LOW': 'green'}.get(priority, 'white')
                console.print(f"\n[{priority_style}]{i}. [{priority}][/{priority_style}] {rec.get('title', 'Recommendation')}")
                console.print(f"   {rec.get('description', '')}")
                if rec.get('fix'):
                    console.print(f"   [dim]Fix:[/dim]")
                    for line in rec.get('fix', '').split('\n')[:5]:
                        console.print(f"   [dim]{line}[/dim]")

        # Save to file if requested
        if output:
            output_path = Path(output)
            output_data = result.to_dict()
            if meta_result:
                output_data["meta_analysis"] = meta_result.to_dict()
            output_path.write_text(json.dumps(output_data, indent=2))
            console.print(f"\n[green]Results saved to: {output}[/green]\n")

        return result

    result = asyncio.run(run_scan())

    # Exit with error code if high severity findings
    if result.get_high_severity_findings():
        sys.exit(1)


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--pattern", "-p", default="*.json", help="File pattern to match")
@click.option("--output", "-o", type=click.Path(), help="Output directory for results")
@click.pass_context
def scan_directory(ctx, directory, pattern, output):
    """Scan all files in a directory matching the pattern."""
    print_banner()

    config = ctx.obj["config"]

    async def run_scan():
        scanner = Scanner(config=config)

        dir_path = Path(directory)
        # Use rglob for recursive search through subdirectories
        files = list(dir_path.rglob(pattern))

        console.print(f"[cyan]Scanning directory: {directory}[/cyan]")
        console.print(f"Found {len(files)} files matching pattern: {pattern}\n")

        results = []
        for file_path in files:
            console.print(f"\n[bold cyan]Scanning: {file_path.name}[/bold cyan]")
            result = await scanner.scan_file(str(file_path))
            results.append(result)
            
            # Print findings for this file
            if result.has_findings():
                console.print(f"[yellow]Found {len(result.findings)} finding(s) in {file_path.name}:[/yellow]")
                print_scan_result(result)
            else:
                console.print(f"[green]✓ No findings in {file_path.name}[/green]")

        # Print overall summary
        console.print("\n" + "="*70)
        console.print("[bold]Overall Scan Summary[/bold]")
        console.print("="*70)
        total_findings = sum(len(r.findings) for r in results)
        high_severity = sum(len(r.get_high_severity_findings()) for r in results)
        medium_severity = sum(len([f for f in r.findings if f.severity == "MEDIUM"]) for r in results)
        low_severity = sum(len([f for f in r.findings if f.severity == "LOW"]) for r in results)

        console.print(f"Files scanned: {len(results)}")
        console.print(f"Total findings: {total_findings}")
        if high_severity > 0:
            console.print(f"  [red]High severity: {high_severity}[/red]")
        if medium_severity > 0:
            console.print(f"  [yellow]Medium severity: {medium_severity}[/yellow]")
        if low_severity > 0:
            console.print(f"  [blue]Low severity: {low_severity}[/blue]")
        console.print()

        # Save results if requested
        if output:
            output_dir = Path(output)
            output_dir.mkdir(parents=True, exist_ok=True)

            for result in results:
                output_file = output_dir / f"{result.target_name}_results.json"
                output_file.write_text(json.dumps(result.to_dict(), indent=2))

            console.print(f"[green]Results saved to: {output}[/green]\n")

        return results

    results = asyncio.run(run_scan())

    # Exit with error code if any high severity findings
    if any(r.get_high_severity_findings() for r in results):
        sys.exit(1)


@cli.command()
@click.pass_context
def list_analyzers(ctx):
    """List available analyzers."""
    print_banner()

    config = ctx.obj["config"]
    scanner = Scanner(config=config)

    analyzers = scanner.get_available_analyzers()

    console.print("[bold]Available Analyzers:[/bold]\n")

    for analyzer_name in analyzers:
        analyzer = scanner.analyzers[analyzer_name]
        console.print(
            f"  • [cyan]{analyzer_name}[/cyan] - {analyzer.__class__.__name__}"
        )

    console.print()


def main():
    """Main entry point for CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
