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

"""Tests for CLI argument parsing (output formats and policy flags)."""

from __future__ import annotations

from a2ascanner.cli.cli import build_parser


class TestCLIParser:
    def test_scan_command_exists(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "test.json"])
        assert args.command == "scan"
        assert str(args.path).endswith("test.json")

    def test_format_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "test.json", "--format", "json"])
        assert args.format is not None
        assert "json" in args.format

    def test_policy_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "test.json", "--policy", "strict"])
        assert args.policy == "strict"

    def test_list_analyzers_command(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["list-analyzers"])
        assert args.command == "list-analyzers"

    def test_generate_policy_command(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["generate-policy", "--preset", "strict", "-o", "out.yaml"])
        assert args.command == "generate-policy"
        assert args.preset == "strict"
        assert str(args.output) == "out.yaml"
