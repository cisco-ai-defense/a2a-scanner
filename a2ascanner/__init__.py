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

"""A2A Scanner

A comprehensive security scanner for Agent-to-Agent (A2A) protocol threats.
Detects vulnerabilities in agent cards, routing, and tool interactions
using multiple analysis engines including YARA rules, heuristic detection,
LLM-powered analysis, and endpoint security testing.
"""

from .core.analyzers.base import BaseAnalyzer, SecurityFinding
from .core.scan_policy import ScanPolicy
from .core.scanner import Scanner
from .config.config import Config

try:
    from ._version import __version__
except ImportError:
    __version__ = "0.0.0"

__all__ = [
    "Scanner",
    "ScanPolicy",
    "Config",
    "BaseAnalyzer",
    "SecurityFinding",
]
