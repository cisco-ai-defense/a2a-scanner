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

"""Rich-based interactive wizard that builds CLI arguments and runs a scan."""

from __future__ import annotations

import shlex
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm, Prompt

from ..data import list_available_packs
from .cli import _dispatch, build_parser, parse_analyzer_list

_FORMAT_CHOICES = ("summary", "json", "markdown", "table", "sarif", "html")
_TARGET_CHOICES = ("file", "directory", "endpoint", "registry")

# Registry keys returned by :meth:`Scanner.get_available_analyzers` / ``--analyzers``.
_KNOWN_ANALYZERS = frozenset(
    (
        "static_analyzer",
        "spec",
        "endpoint",
        "llm",
        "heuristic",
    )
)


def run_wizard() -> int:
    """Prompt for scan options, build argv, parse with the main CLI parser, and dispatch."""
    console = Console()
    console.print("[bold cyan]A2A Scanner - Interactive Wizard[/bold cyan]\n")

    target = Prompt.ask(
        "Scan target type",
        choices=list(_TARGET_CHOICES),
        default="file",
    )

    if target == "file":
        path_raw = Prompt.ask("Path to file (agent card JSON or text)")
        path = Path(path_raw).expanduser()
        if not path.is_file():
            console.print(f"[red]Error: not a file: {path}[/red]")
            return 1
        cmd: list[str] = ["scan", str(path)]
    elif target == "directory":
        dir_raw = Prompt.ask("Directory to scan")
        directory = Path(dir_raw).expanduser()
        if not directory.is_dir():
            console.print(f"[red]Error: not a directory: {directory}[/red]")
            return 1
        pattern = Prompt.ask("Glob pattern (recursive)", default="*.json")
        cmd = ["scan-all", str(directory), "--pattern", pattern]
    elif target == "endpoint":
        url = Prompt.ask("Agent HTTPS URL")
        cmd = ["scan-endpoint", url]
        if Confirm.ask("Disable TLS certificate verification?", default=False):
            cmd.append("--no-verify-ssl")
        token = Prompt.ask("Bearer token (optional)", default="").strip()
        if token:
            cmd.extend(["--bearer-token", token])
    else:
        reg_url = Prompt.ask("Registry JSON URL")
        cmd = ["scan-registry", reg_url]

    console.print(
        "\n[dim]Analyzers: leave empty to run all enabled by policy; "
        "or comma-separated registry keys: static_analyzer, spec, endpoint, llm, heuristic.[/dim]"
    )
    analyzers_raw = Prompt.ask("Restrict analyzers (optional)", default="").strip()
    if analyzers_raw:
        parsed = parse_analyzer_list([analyzers_raw])
        if parsed:
            unknown = [a for a in parsed if a not in _KNOWN_ANALYZERS]
            if unknown:
                console.print(
                    f"[yellow]Warning: unknown analyzer name(s) {unknown!r} — they may be ignored.[/yellow]"
                )
            for a in parsed:
                cmd.extend(["--analyzers", a])

    fmt = Prompt.ask("Output format", choices=list(_FORMAT_CHOICES), default="summary")
    cmd.extend(["--format", fmt])

    out_default = ""
    if fmt in ("json", "markdown", "table", "sarif", "html") and Confirm.ask(
        "Write primary report to a file?", default=False
    ):
        out_default = Prompt.ask("Output file path")
    if out_default.strip():
        cmd.extend(["-o", out_default.strip()])

    preset_choices = ["strict", "balanced", "permissive", "custom"]
    pol = Prompt.ask(
        "Policy preset (or choose custom for a YAML path)",
        choices=preset_choices,
        default="balanced",
    )
    if pol == "custom":
        ppath = Prompt.ask("Path to policy YAML")
        if not Path(ppath).expanduser().is_file():
            console.print(f"[red]Error: policy file not found: {ppath}[/red]")
            return 1
        cmd.extend(["--policy", ppath])
    else:
        cmd.extend(["--policy", pol])

    packs_known = list_available_packs()
    if packs_known:
        console.print(f"[dim]Available rule packs: {', '.join(packs_known)}[/dim]")
    packs_raw = Prompt.ask(
        "Extra rule packs (space-separated names, or leave empty)",
        default="",
    ).strip()
    if packs_raw:
        cmd.append("--rule-packs")
        cmd.extend(shlex.split(packs_raw))

    want_llm = Confirm.ask(
        "Enable LLM analyzer (--use-llm)? Requires API key in environment.",
        default=False,
    )
    if want_llm:
        cmd.append("--use-llm")

    if Confirm.ask("Enable verbose logging (--verbose)?", default=False):
        cmd.append("--verbose")

    if Confirm.ask("Development mode (--dev: relaxed TLS/hosts)?", default=False):
        cmd = ["--dev", *cmd]

    parser = build_parser()
    args = parser.parse_args(cmd)

    console.print(f"\n[green]Running:[/green] a2a-scanner {' '.join(shlex.quote(c) for c in cmd)}\n")

    return _dispatch(args)
