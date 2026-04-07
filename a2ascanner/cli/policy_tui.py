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

"""Textual TUI for editing :class:`~a2ascanner.core.scan_policy.ScanPolicy` YAML."""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    RadioButton,
    RadioSet,
    Static,
    Switch,
    TextArea,
)

from ..core.scan_policy import (
    AnalyzerPolicy,
    FindingOutputPolicy,
    LLMAnalysisPolicy,
    ScanPolicy,
)

_SEVERITY_OPTIONS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def run_policy_tui(output_path: str = "scan_policy.yaml", input_path: str | None = None) -> int:
    """Run the interactive policy editor; write YAML to *output_path* on save.

    When *input_path* is set, load that policy into the form. Returns 0 on save,
    1 on cancel or write error.
    """
    app = PolicyConfigApp(output_path=output_path, input_path=input_path)
    app.run()
    return app.exit_code


class PolicyConfigApp(App[None]):
    """Interactive scan policy editor."""

    TITLE = "A2A Scanner - Policy Configuration"
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
    ]
    CSS = """
    Screen {
        align: center middle;
    }
    #main {
        width: 88;
        height: 90%;
        border: heavy $primary;
        padding: 1 2;
    }
    .section {
        margin-top: 1;
        text-style: bold;
    }
    .hint {
        color: $text-muted;
        margin-top: 0;
        margin-bottom: 1;
    }
    #actions {
        margin-top: 1;
        height: auto;
    }
    TextArea {
        height: 6;
        border: solid $surface;
    }
    RadioSet {
        margin-bottom: 1;
    }
    """

    def __init__(self, output_path: str, input_path: str | None) -> None:
        super().__init__()
        self.output_path = output_path
        self.input_path = input_path
        self.exit_code = 0
        # Skip the first RadioSet.Changed so we do not replace a loaded file with "balanced".
        self._last_preset_index: int | None = None
        if input_path:
            self.policy = ScanPolicy.from_yaml(Path(input_path))
        else:
            self.policy = ScanPolicy.from_preset("balanced")

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main"):
            with VerticalScroll():
                yield Static("Configure analyzers, disabled rules, severity overrides, and LLM options.", classes="hint")
                yield Label("Base preset", classes="section")
                if self.input_path:
                    yield Static(
                        f"Loaded: {self.input_path}. Choosing a preset replaces all fields below.",
                        classes="hint",
                    )
                yield RadioSet(
                    RadioButton("Balanced", value=True),
                    RadioButton("Strict"),
                    RadioButton("Permissive"),
                    id="preset_rs",
                )
                yield Label("Analyzers", classes="section")
                with Horizontal():
                    with Vertical():
                        yield Label("Static")
                        yield Switch(value=self.policy.analyzers.static, id="sw_static")
                    with Vertical():
                        yield Label("Spec")
                        yield Switch(value=self.policy.analyzers.spec, id="sw_spec")
                    with Vertical():
                        yield Label("Endpoint")
                        yield Switch(value=self.policy.analyzers.endpoint, id="sw_endpoint")
                    with Vertical():
                        yield Label("LLM")
                        yield Switch(value=self.policy.analyzers.llm, id="sw_llm")
                yield Label("Policy metadata", classes="section")
                with Horizontal():
                    with Vertical():
                        yield Label("Name")
                        yield Input(self.policy.policy_name, id="in_policy_name")
                    with Vertical():
                        yield Label("Version")
                        yield Input(self.policy.policy_version, id="in_policy_version")
                yield Label("Description")
                yield Input(self.policy.description, id="in_description")
                yield Label("Disabled rules (one rule id per line)", classes="section")
                yield TextArea("\n".join(self.policy.disabled_rules), id="ta_disabled")
                yield Label("Severity overrides (rule_id: SEVERITY per line)", classes="section")
                yield Static(
                    f"Allowed severities: {', '.join(_SEVERITY_OPTIONS)}",
                    classes="hint",
                )
                override_lines = "\n".join(f"{k}: {v}" for k, v in self.policy.severity_overrides.items())
                yield TextArea(override_lines, id="ta_overrides")
                yield Label("Finding output", classes="section")
                with Horizontal():
                    with Vertical():
                        yield Label("Dedupe exact")
                        yield Switch(value=self.policy.finding_output.dedupe_exact_findings, id="sw_dedupe_exact")
                    with Vertical():
                        yield Label("Dedupe same loc")
                        yield Switch(value=self.policy.finding_output.dedupe_same_issue_per_location, id="sw_dedupe_loc")
                    with Vertical():
                        yield Label("Fingerprint")
                        yield Switch(value=self.policy.finding_output.attach_policy_fingerprint, id="sw_fingerprint")
                    with Vertical():
                        yield Label("Co-occurrence")
                        yield Switch(value=self.policy.finding_output.annotate_same_path_rule_cooccurrence, id="sw_cooccur")
                yield Label("LLM analysis", classes="section")
                with Horizontal():
                    with Vertical():
                        yield Label("Model (empty = default)")
                        yield Input(self.policy.llm_analysis.model or "", id="in_llm_model", placeholder="e.g. gpt-4o")
                    with Vertical():
                        yield Label("Max output tokens")
                        yield Input(str(self.policy.llm_analysis.max_output_tokens), id="in_max_tokens")
            with Horizontal(id="actions"):
                yield Button("Save", variant="primary", id="btn_save")
                yield Button("Cancel", id="btn_cancel")
        yield Footer()

    def on_mount(self) -> None:
        self._sync_switches_from_policy()

    def _sync_switches_from_policy(self) -> None:
        self.query_one("#sw_static", Switch).value = self.policy.analyzers.static
        self.query_one("#sw_spec", Switch).value = self.policy.analyzers.spec
        self.query_one("#sw_endpoint", Switch).value = self.policy.analyzers.endpoint
        self.query_one("#sw_llm", Switch).value = self.policy.analyzers.llm
        self.query_one("#in_policy_name", Input).value = self.policy.policy_name
        self.query_one("#in_policy_version", Input).value = self.policy.policy_version
        self.query_one("#in_description", Input).value = self.policy.description
        self.query_one("#ta_disabled", TextArea).text = "\n".join(self.policy.disabled_rules)
        override_lines = "\n".join(f"{k}: {v}" for k, v in self.policy.severity_overrides.items())
        self.query_one("#ta_overrides", TextArea).text = override_lines
        self.query_one("#in_llm_model", Input).value = self.policy.llm_analysis.model or ""
        self.query_one("#in_max_tokens", Input).value = str(self.policy.llm_analysis.max_output_tokens)
        self.query_one("#sw_dedupe_exact", Switch).value = self.policy.finding_output.dedupe_exact_findings
        self.query_one("#sw_dedupe_loc", Switch).value = self.policy.finding_output.dedupe_same_issue_per_location
        self.query_one("#sw_fingerprint", Switch).value = self.policy.finding_output.attach_policy_fingerprint
        self.query_one("#sw_cooccur", Switch).value = self.policy.finding_output.annotate_same_path_rule_cooccurrence

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id != "preset_rs":
            return
        idx = event.radio_set.pressed_index
        if self._last_preset_index is None:
            self._last_preset_index = idx
            return
        if idx == self._last_preset_index:
            return
        self._last_preset_index = idx
        names = ("balanced", "strict", "permissive")
        if 0 <= idx < len(names):
            self.policy = ScanPolicy.from_preset(names[idx])
            self._sync_switches_from_policy()

    def _parse_disabled_rules(self, raw: str) -> list[str]:
        out: list[str] = []
        for line in raw.splitlines():
            s = line.strip()
            if s:
                out.append(s)
        return out

    def _parse_overrides(self, raw: str) -> dict[str, str]:
        overrides: dict[str, str] = {}
        for line in raw.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if ":" not in s:
                continue
            rule_id, sev = s.split(":", 1)
            rule_id = rule_id.strip()
            sev = sev.strip().upper()
            if rule_id and sev in _SEVERITY_OPTIONS:
                overrides[rule_id] = sev
        return overrides

    def _collect_policy(self) -> ScanPolicy:
        max_raw = self.query_one("#in_max_tokens", Input).value.strip()
        try:
            max_tokens = int(max_raw) if max_raw else 8192
        except ValueError:
            max_tokens = 8192

        model_raw = self.query_one("#in_llm_model", Input).value.strip()
        llm_on = self.query_one("#sw_llm", Switch).value

        analyzers = AnalyzerPolicy(
            static=self.query_one("#sw_static", Switch).value,
            spec=self.query_one("#sw_spec", Switch).value,
            endpoint=self.query_one("#sw_endpoint", Switch).value,
            llm=llm_on,
        )
        llm_analysis = LLMAnalysisPolicy(
            enabled=llm_on,
            model=model_raw or None,
            max_output_tokens=max_tokens,
        )
        return ScanPolicy(
            policy_name=self.query_one("#in_policy_name", Input).value.strip() or self.policy.policy_name,
            policy_version=self.query_one("#in_policy_version", Input).value.strip() or self.policy.policy_version,
            description=self.query_one("#in_description", Input).value.strip(),
            disabled_rules=self._parse_disabled_rules(self.query_one("#ta_disabled", TextArea).text),
            severity_overrides=self._parse_overrides(self.query_one("#ta_overrides", TextArea).text),
            analyzers=analyzers,
            llm_analysis=llm_analysis,
            finding_output=FindingOutputPolicy(
                dedupe_exact_findings=self.query_one("#sw_dedupe_exact", Switch).value,
                dedupe_same_issue_per_location=self.query_one("#sw_dedupe_loc", Switch).value,
                attach_policy_fingerprint=self.query_one("#sw_fingerprint", Switch).value,
                annotate_same_path_rule_cooccurrence=self.query_one("#sw_cooccur", Switch).value,
            ),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_save":
            try:
                policy = self._collect_policy()
                out = Path(self.output_path)
                out.parent.mkdir(parents=True, exist_ok=True)
                policy.to_yaml(out)
                self.exit_code = 0
            except OSError:
                self.exit_code = 1
            self.exit()
        elif event.button.id == "btn_cancel":
            self.exit_code = 1
            self.exit()

    def action_quit(self) -> None:
        self.exit_code = 1
        self.exit()
