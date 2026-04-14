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

"""Argparse-based CLI for A2A Scanner (subcommand layout aligned with skill-scanner)."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown

from ..config.config import Config
from ..core.analyzer_factory import build_analyzers
from ..core.models import ScanResult
from ..core.reporters import (
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
    SARIFReporter,
    TableReporter,
)
from ..core.scan_policy import ScanPolicy
from ..core.scanner import Scanner
from ..utils.logging_config import setup_logging

logger = logging.getLogger("a2ascanner.cli")

console = Console()

_FORMAT_CHOICES = ("summary", "json", "markdown", "table", "sarif", "html")
_FAIL_SEVERITY_CHOICES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "SAFE": 0}


def parse_analyzer_list(values: list[str] | None) -> list[str] | None:
    """Flatten comma-separated and repeated --analyzers values."""
    if not values:
        return None
    out: list[str] = []
    for raw in values:
        for part in raw.split(","):
            p = part.strip()
            if p:
                out.append(p)
    return out or None


def _load_policy(args: argparse.Namespace) -> ScanPolicy:
    """Load :class:`ScanPolicy` from ``--policy`` or built-in default."""
    policy_value = getattr(args, "policy", None)
    if policy_value:
        presets = {p.lower() for p in ScanPolicy.preset_names()}
        if policy_value.lower() in presets:
            policy = ScanPolicy.from_preset(policy_value)
            logger.info("Using preset policy: %s", policy.policy_name)
        else:
            path = Path(policy_value)
            if not path.is_file():
                print(f"Error: Policy file not found: {policy_value}", file=sys.stderr)
                sys.exit(1)
            try:
                policy = ScanPolicy.from_yaml(path)
            except Exception as e:
                print(f"Error loading policy file: {e}", file=sys.stderr)
                sys.exit(1)
    else:
        policy = ScanPolicy.default()

    if not getattr(args, "verbose", False):
        policy.finding_output.attach_policy_fingerprint = False
        policy.finding_output.annotate_same_path_rule_cooccurrence = False

    return policy


def _build_analyzers(
    policy: ScanPolicy,
    args: argparse.Namespace,
    config: Config,
    status: Callable[[str], None],
) -> list[Any]:
    """Build analyzers via :func:`a2ascanner.core.analyzer_factory.build_analyzers`."""
    from ..data import resolve_rule_packs

    extra_rules_dirs: list[Path] | None = None
    pack_names = getattr(args, "rule_packs", None) or []
    if pack_names:
        if pack_names == ["list"]:
            from ..data import list_available_packs

            packs = list_available_packs()
            if packs:
                print("Available rule packs:")
                for p in packs:
                    print(f"  - {p}")
            else:
                print("No additional rule packs available.")
            sys.exit(0)
        extra_rules_dirs = resolve_rule_packs(list(pack_names))
        status(f"Loading additional rule packs: {', '.join(pack_names)}")

    custom_rules = getattr(args, "custom_rules", None)
    use_llm = bool(getattr(args, "use_llm", False))

    analyzers = build_analyzers(
        policy,
        config=config,
        custom_yara_rules_path=custom_rules,
        extra_rules_dirs=extra_rules_dirs,
        use_llm=use_llm,
        use_endpoint=bool(getattr(args, "use_endpoint_internal", False)),
    )

    return analyzers


def _get_formats(args: argparse.Namespace) -> list[str]:
    raw = getattr(args, "format", None)
    if not raw:
        return ["summary"]
    if isinstance(raw, list):
        return raw
    return [raw]


def _make_status_printer(args: argparse.Namespace) -> Callable[[str], None]:
    formats = _get_formats(args)
    machine = any(f in formats for f in ("json", "sarif"))

    def _print(msg: str) -> None:
        print(msg, file=sys.stderr if machine else sys.stdout)

    return _print


def _format_single(fmt: str, args: argparse.Namespace, result: ScanResult) -> str:
    """Render *result* for one output format."""
    if fmt == "json":
        return JSONReporter(pretty=not getattr(args, "compact", False)).generate_report(result)
    if fmt == "markdown":
        return MarkdownReporter().generate_report(result)
    if fmt == "table":
        dedupe = not getattr(args, "no_deduplicate", False)
        return TableReporter(deduplicate=dedupe).generate_report(result)
    if fmt == "sarif":
        return SARIFReporter(pretty=not getattr(args, "compact", False)).generate_report(result)
    if fmt == "html":
        return HTMLReporter().generate_report(result)

    from ..core.results import RESULT_PROCESSOR, OutputMode

    if getattr(args, "detailed", False):
        return RESULT_PROCESSOR.format_for_display(result, OutputMode.DETAILED)
    return RESULT_PROCESSOR.format_for_display(result, OutputMode.SUMMARY)


def _format_output(args: argparse.Namespace, result: ScanResult) -> str:
    formats = _get_formats(args)
    return _format_single(formats[0], args, result)


def _write_output(args: argparse.Namespace, output: str, result: ScanResult) -> None:
    """Write primary output and any additional ``--format`` outputs."""
    formats = _get_formats(args)
    primary_fmt = formats[0] if formats else "summary"
    render_md = sys.stdout.isatty()

    fmt_to_attr = {
        "json": "output_json",
        "sarif": "output_sarif",
        "markdown": "output_markdown",
        "html": "output_html",
        "table": "output_table",
    }
    primary_file = getattr(args, fmt_to_attr.get(primary_fmt, ""), None)
    if not primary_file:
        primary_file = getattr(args, "output", None)

    if primary_file:
        Path(primary_file).write_text(output, encoding="utf-8")
        print(f"Report saved to: {primary_file}", file=sys.stderr)
    else:
        if primary_fmt == "markdown" and render_md:
            console.print(Markdown(output))
        else:
            print(output)

    if len(formats) > 1:
        for fmt in formats[1:]:
            extra = _format_single(fmt, args, result)
            path = getattr(args, fmt_to_attr.get(fmt, ""), None)
            if path:
                Path(path).write_text(extra, encoding="utf-8")
                print(f"{fmt.upper()} report saved to: {path}", file=sys.stderr)
            else:
                if fmt == "markdown" and render_md:
                    console.print(Markdown(extra))
                else:
                    print(extra)


def _finding_at_or_above(finding: Any, threshold: str) -> bool:
    sev = (getattr(finding, "severity", "") or "").upper()
    t = threshold.upper()
    return _SEVERITY_RANK.get(sev, 0) >= _SEVERITY_RANK.get(t, 0)


def _should_fail(result: ScanResult, threshold: str | None) -> bool:
    if not threshold:
        return False
    return any(_finding_at_or_above(f, threshold) for f in result.findings)


def _print_banner() -> None:
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           A2A Scanner                                     ║
║     Agent-to-Agent Protocol Threat Detection              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="bold cyan")


def _apply_dev_warning(dev: bool) -> None:
    if not dev:
        return
    console.print("[yellow]WARNING: Development mode enabled:[/yellow]")
    console.print("   - Localhost URLs allowed")
    console.print("   - Private IP addresses allowed")
    console.print("   - SSL certificate verification disabled")
    console.print("   - HTTP connections allowed")
    console.print("[yellow]   DO NOT use in production![/yellow]\n")


def _add_common_scan_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--format",
        action="append",
        choices=_FORMAT_CHOICES,
        help="Output format (repeat for multiple)",
    )
    p.add_argument("-o", "--output", help="Primary output file path")
    p.add_argument("--output-json", metavar="PATH", help="Write JSON report to PATH")
    p.add_argument("--output-sarif", metavar="PATH", help="Write SARIF report to PATH")
    p.add_argument("--output-markdown", metavar="PATH", help="Write Markdown report to PATH")
    p.add_argument("--output-html", metavar="PATH", help="Write HTML report to PATH")
    p.add_argument("--output-table", metavar="PATH", help="Write table (text) report to PATH")
    p.add_argument(
        "--policy",
        metavar="PRESET_OR_PATH",
        help="Policy preset (strict, balanced, permissive) or path to YAML",
    )
    p.add_argument(
        "--rule-packs",
        nargs="*",
        metavar="PACK",
        help="Additional rule packs (use 'list' to print available names)",
    )
    p.add_argument("--custom-rules", metavar="PATH", help="Custom YARA rules directory or file root")
    p.add_argument("--use-llm", action="store_true", help="Enable LLM analyzer when API key is set")
    p.add_argument(
        "--enable-meta",
        action="store_true",
        help="Run LLM meta-analysis to filter false positives (requires API key)",
    )
    p.add_argument(
        "--fail-on-severity",
        choices=_FAIL_SEVERITY_CHOICES,
        help="Exit with code 1 if any finding is at or above this severity",
    )
    p.add_argument("--verbose", action="store_true", help="Verbose logging and richer policy output")
    p.add_argument("--compact", action="store_true", help="Compact JSON / SARIF (no indentation)")
    p.add_argument("--detailed", action="store_true", help="Use detailed text output for summary mode")
    p.add_argument(
        "--no-deduplicate",
        action="store_true",
        help="Disable deduplication in table output",
    )
    p.add_argument(
        "--analyzers",
        "-a",
        action="append",
        dest="analyzers",
        metavar="NAME",
        help="Restrict to named analyzers (repeat or comma-separated)",
    )


async def _run_meta_if_requested(
    scanner: Scanner,
    config: Config,
    result: ScanResult,
    content: str,
    args: argparse.Namespace,
) -> ScanResult:
    """Optionally run meta-analysis like the legacy Click CLI."""
    if not getattr(args, "enable_meta", False) or not result.has_findings():
        return result

    api_key = getattr(args, "meta_api_key", None) or config.meta_llm_api_key
    if not api_key:
        console.print(
            "[yellow]Meta-analysis requires an LLM API key "
            "(A2A_SCANNER_META_LLM_API_KEY or A2A_SCANNER_LLM_API_KEY).[/yellow]\n"
        )
        return result

    if getattr(args, "meta_api_key", None):
        config.meta_llm_api_key = args.meta_api_key
    if getattr(args, "meta_model", None):
        config.meta_llm_model = args.meta_model

    console.print("\n[cyan]Running LLM meta-analysis...[/cyan]")
    try:
        meta_result = await scanner.run_meta_analysis(result, content)
        new_result = scanner.apply_meta_analysis(result, meta_result)
        summary = scanner.meta_analyzer.get_summary_report(meta_result) if scanner.meta_analyzer else {}
        console.print("\n[bold]Meta-Analysis Summary:[/bold]")
        console.print(f"  Original findings: {summary.get('total_original_findings', '—')}")
        console.print(f"  Validated findings: {summary.get('validated_findings_count', '—')}")
        console.print(f"  False positives removed: {summary.get('false_positives_count', '—')}")
        console.print(f"  Recommendations: {summary.get('recommendations_count', '—')}")
        risk = summary.get("overall_risk", {})
        if risk:
            level = risk.get("risk_level", "UNKNOWN")
            console.print(f"  Overall Risk: [bold]{level}[/bold]")
        console.print()
        if meta_result.recommendations:
            console.print("\n[bold cyan]Recommendations:[/bold cyan]")
            for i, rec in enumerate(meta_result.recommendations, 1):
                console.print(f"\n{i}. [{rec.get('priority', 'MEDIUM')}] {rec.get('title', '')}")
                console.print(f"   {rec.get('description', '')}")
        return new_result
    except Exception as e:
        console.print(f"[red]Meta-analysis failed: {e}[/red]\n")
        return result


def scan_command(args: argparse.Namespace) -> int:
    """Scan a single file (agent card JSON or raw content)."""
    path = Path(args.path)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    _maybe_show_banner(args)
    config = Config()
    config.log_level = "DEBUG" if args.debug else "WARNING"
    config.dev_mode = args.dev
    setup_logging(config.log_level)
    _apply_dev_warning(args.dev)

    status = _make_status_printer(args)
    policy = _load_policy(args)
    args.use_endpoint_internal = False
    analyzers = _build_analyzers(policy, args, config, status)

    scanner = Scanner(config=config, policy=policy, analyzers=analyzers)

    async def _go() -> ScanResult:
        raw = path.read_text(encoding="utf-8", errors="replace")
        analyzer_names = parse_analyzer_list(getattr(args, "analyzers", None))
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            result = await scanner.scan_file(str(path), analyzers=analyzer_names)
            return await _run_meta_if_requested(scanner, config, result, raw, args)

        if isinstance(data, dict) and any(k in data for k in ("id", "name", "url")):
            result = await scanner.scan_agent_card(data, analyzers=analyzer_names)
            return await _run_meta_if_requested(scanner, config, result, raw, args)
        result = await scanner.scan_file(str(path), analyzers=analyzer_names)
        return await _run_meta_if_requested(scanner, config, result, raw, args)

    result = asyncio.run(_go())

    out = _format_output(args, result)
    _write_output(args, out, result)

    if _should_fail(result, getattr(args, "fail_on_severity", None)):
        return 1
    return 0


def scan_all_command(args: argparse.Namespace) -> int:
    """Scan files under a directory."""
    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Error: not a directory: {directory}", file=sys.stderr)
        return 1

    _maybe_show_banner(args)
    config = Config()
    config.log_level = "DEBUG" if args.debug else "WARNING"
    config.dev_mode = args.dev
    setup_logging(config.log_level)
    _apply_dev_warning(args.dev)

    status = _make_status_printer(args)
    policy = _load_policy(args)
    args.use_endpoint_internal = False
    analyzers = _build_analyzers(policy, args, config, status)
    scanner = Scanner(config=config, policy=policy, analyzers=analyzers)

    pattern = getattr(args, "pattern", "*.json")
    files = list(directory.rglob(pattern))
    console.print(f"[cyan]Scanning directory:[/cyan] {directory} ({len(files)} files)\n")

    any_fail = False
    analyzer_names = parse_analyzer_list(getattr(args, "analyzers", None))

    async def _scan_all() -> None:
        nonlocal any_fail
        for fp in files:
            console.print(f"[bold cyan]{fp.name}[/bold cyan]")
            result = await scanner.scan_file(str(fp), analyzers=analyzer_names)
            if result.has_findings():
                console.print(f"[yellow]{len(result.findings)} finding(s)[/yellow]")
                print(_format_single("table", args, result))
            else:
                console.print("[green]No findings[/green]")
            if _should_fail(result, getattr(args, "fail_on_severity", None)):
                any_fail = True
            out_dir = getattr(args, "output_dir", None)
            if out_dir:
                out_p = Path(out_dir)
                out_p.mkdir(parents=True, exist_ok=True)
                (out_p / f"{result.target_name}_results.json").write_text(
                    JSONReporter().generate_report(result), encoding="utf-8"
                )

    asyncio.run(_scan_all())

    return 1 if any_fail else 0


def scan_endpoint_command(args: argparse.Namespace) -> int:
    """Scan a live agent endpoint."""
    _maybe_show_banner(args)
    config = Config()
    config.log_level = "DEBUG" if args.debug else "WARNING"
    config.dev_mode = args.dev
    setup_logging(config.log_level)
    _apply_dev_warning(args.dev)

    status = _make_status_printer(args)
    policy = _load_policy(args)
    args.use_endpoint_internal = True
    analyzers = _build_analyzers(policy, args, config, status)
    scanner = Scanner(config=config, policy=policy, analyzers=analyzers)

    async def _go() -> ScanResult:
        return await scanner.scan_endpoint(
            args.endpoint_url,
            timeout=getattr(args, "timeout", 30.0),
            bearer_token=getattr(args, "bearer_token", None),
            verify_ssl=not getattr(args, "no_verify_ssl", False),
        )

    result = asyncio.run(_go())
    out = _format_output(args, result)
    _write_output(args, out, result)
    if _should_fail(result, getattr(args, "fail_on_severity", None)):
        return 1
    return 0


def scan_registry_command(args: argparse.Namespace) -> int:
    """Scan a remote agent registry URL."""
    _maybe_show_banner(args)
    config = Config()
    config.log_level = "DEBUG" if args.debug else "WARNING"
    config.dev_mode = args.dev
    setup_logging(config.log_level)
    _apply_dev_warning(args.dev)

    status = _make_status_printer(args)
    policy = _load_policy(args)
    args.use_endpoint_internal = False
    analyzers = _build_analyzers(policy, args, config, status)
    scanner = Scanner(config=config, policy=policy, analyzers=analyzers)

    async def _go() -> ScanResult:
        return await scanner.scan_registry(
            args.registry_url,
            analyzers=parse_analyzer_list(getattr(args, "analyzers", None)),
        )

    result = asyncio.run(_go())
    out = _format_output(args, result)
    _write_output(args, out, result)
    if _should_fail(result, getattr(args, "fail_on_severity", None)):
        return 1
    return 0


def list_analyzers_command(args: argparse.Namespace) -> int:
    """Print available analyzers for the active policy."""
    _maybe_show_banner(args)
    config = Config()
    config.log_level = "DEBUG" if args.debug else "WARNING"
    config.dev_mode = args.dev
    setup_logging(config.log_level)

    policy = _load_policy(args)
    args.use_endpoint_internal = False
    status = _make_status_printer(args)
    analyzers = _build_analyzers(policy, args, config, status)
    scanner = Scanner(config=config, policy=policy, analyzers=analyzers)

    console.print("[bold]Available analyzers[/bold]\n")
    for name in scanner.get_available_analyzers():
        a = scanner.analyzers[name]
        console.print(f"  • [cyan]{name}[/cyan] — {a.__class__.__name__}")
    console.print()
    return 0


def validate_rules_command(args: argparse.Namespace) -> int:
    """Validate YAML signature rules and pack manifests."""
    import yaml

    from ..core.rule_registry import PackLoader
    from ..core.rules.patterns import RuleLoader, SecurityRule
    from ..data import DATA_DIR

    roots = [Path(p) for p in args.paths] if args.paths else [DATA_DIR / "packs"]
    errors = 0

    for root in roots:
        if not root.exists():
            print(f"Error: path not found: {root}", file=sys.stderr)
            errors += 1
            continue
        if root.is_file():
            print(f"Skipping non-directory: {root}", file=sys.stderr)
            continue
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            manifest = child / "pack.yaml"
            if manifest.is_file():
                try:
                    PackLoader.load_pack(child)
                    print(f"OK pack manifest: {manifest}")
                except Exception as e:
                    print(f"FAIL {manifest}: {e}", file=sys.stderr)
                    errors += 1
            sig_dir = child / "signatures"
            if sig_dir.is_dir():
                loader = RuleLoader(signatures_dirs=[sig_dir])
                try:
                    rules = loader.load_rules()
                    print(f"OK signatures in {sig_dir} ({len(rules)} rules)")
                except Exception as e:
                    print(f"FAIL {sig_dir}: {e}", file=sys.stderr)
                    errors += 1
                    continue
                for yml in sorted(list(sig_dir.glob("*.yml")) + list(sig_dir.glob("*.yaml"))):
                    try:
                        text = yml.read_text(encoding="utf-8")
                        data = yaml.safe_load(text)
                        entries = RuleLoader._extract_rule_list(data)
                        for entry in entries:
                            SecurityRule(entry)
                    except Exception as e:
                        print(f"FAIL {yml}: {e}", file=sys.stderr)
                        errors += 1

    return 1 if errors else 0


def generate_policy_command(args: argparse.Namespace) -> int:
    """Write a policy YAML from a preset or defaults."""
    out = Path(args.output)
    try:
        if args.preset:
            policy = ScanPolicy.from_preset(args.preset)
        else:
            policy = ScanPolicy.default()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    policy.to_yaml(out)
    print(f"Wrote policy to {out}")
    return 0


def configure_policy_command(args: argparse.Namespace) -> int:
    """Interactive policy TUI."""
    try:
        from .policy_tui import run_policy_tui
    except ImportError:
        print(
            "Error: policy TUI is not available (missing a2ascanner.cli.policy_tui).",
            file=sys.stderr,
        )
        return 1
    out = getattr(args, "policy_tui_output", None) or "scan_policy.yaml"
    inp = getattr(args, "policy_tui_input", None)
    return run_policy_tui(output_path=out, input_path=inp)


def interactive_command(args: argparse.Namespace) -> int:
    """Launch the interactive wizard."""
    try:
        from .wizard import run_wizard
    except ImportError:
        print(
            "Error: interactive wizard is not available (missing a2ascanner.cli.wizard).",
            file=sys.stderr,
        )
        return 1
    return run_wizard()


def _maybe_show_banner(args: argparse.Namespace) -> None:
    formats = _get_formats(args)
    if any(f in formats for f in ("json", "sarif")):
        return
    _print_banner()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="a2a-scanner",
        description="Detect threats in Agent-to-Agent (A2A) protocol artifacts and endpoints.",
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    p.add_argument(
        "--dev",
        action="store_true",
        help="Development mode (localhost/private IPs, relaxed TLS)",
    )

    sub = p.add_subparsers(dest="command", required=False)

    s_scan = sub.add_parser("scan", help="Scan a single file or agent card")
    s_scan.add_argument("path", type=Path, help="File to scan")
    _add_common_scan_flags(s_scan)
    s_scan.add_argument("--meta-model", help="Model for meta-analysis LLM")
    s_scan.add_argument("--meta-api-key", help="API key for meta-analysis LLM")

    s_all = sub.add_parser("scan-all", help="Scan files in a directory")
    s_all.add_argument("directory", type=Path, help="Directory to scan")
    s_all.add_argument("--pattern", "-p", default="*.json", help="Glob pattern (recursive)")
    s_all.add_argument("--output-dir", metavar="DIR", help="Write per-file JSON results here")
    _add_common_scan_flags(s_all)

    s_ep = sub.add_parser("scan-endpoint", help="Scan a live A2A endpoint")
    s_ep.add_argument("endpoint_url", help="HTTPS URL of the agent")
    s_ep.add_argument("--timeout", "-t", type=float, default=30.0, help="HTTP timeout (seconds)")
    s_ep.add_argument("--bearer-token", help="Bearer token for authenticated requests")
    s_ep.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    _add_common_scan_flags(s_ep)

    s_reg = sub.add_parser("scan-registry", help="Scan an agent registry URL")
    s_reg.add_argument("registry_url", help="Registry JSON URL")
    _add_common_scan_flags(s_reg)

    s_list = sub.add_parser("list-analyzers", help="List analyzers enabled by the current policy")
    _add_common_scan_flags(s_list)

    s_val = sub.add_parser("validate-rules", help="Validate rule signatures and pack manifests")
    s_val.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Pack roots (default: packaged data/packs)",
    )

    s_gen = sub.add_parser("generate-policy", help="Generate a policy YAML file")
    s_gen.add_argument(
        "--preset",
        choices=sorted(ScanPolicy.preset_names()),
        help="Named preset (omit for default/balanced)",
    )
    s_gen.add_argument("-o", "--output", required=True, help="Output YAML path")

    s_cfg = sub.add_parser("configure-policy", help="Interactive policy editor (TUI)")
    s_cfg.add_argument(
        "-o",
        "--output",
        dest="policy_tui_output",
        metavar="PATH",
        default="scan_policy.yaml",
        help="Path to write policy YAML (default: scan_policy.yaml)",
    )
    s_cfg.add_argument(
        "-i",
        "--input",
        dest="policy_tui_input",
        metavar="PATH",
        help="Load existing policy YAML to edit",
    )
    sub.add_parser("interactive", help="Interactive scan wizard")

    return p


def build_parser() -> argparse.ArgumentParser:
    """Build the root CLI parser (for programmatic use, e.g. the interactive wizard)."""
    return _build_parser()


def dispatch(args: argparse.Namespace) -> int:
    """Route parsed CLI arguments to the appropriate subcommand handler."""
    cmd = args.command
    if cmd == "scan":
        return scan_command(args)
    if cmd == "scan-all":
        return scan_all_command(args)
    if cmd == "scan-endpoint":
        return scan_endpoint_command(args)
    if cmd == "scan-registry":
        return scan_registry_command(args)
    if cmd == "list-analyzers":
        return list_analyzers_command(args)
    if cmd == "validate-rules":
        return validate_rules_command(args)
    if cmd == "generate-policy":
        return generate_policy_command(args)
    if cmd == "configure-policy":
        return configure_policy_command(args)
    if cmd == "interactive":
        return interactive_command(args)
    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    log_level = "DEBUG" if getattr(args, "debug", False) else "WARNING"
    setup_logging(log_level)

    if args.command is None:
        if sys.stdin.isatty() and sys.stdout.isatty():
            try:
                from .wizard import run_wizard
            except ImportError:
                parser.print_help()
                raise SystemExit(2)
            raise SystemExit(run_wizard())
        parser.print_help()
        raise SystemExit(2)

    raise SystemExit(dispatch(args))


if __name__ == "__main__":
    main()
