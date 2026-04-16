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

"""Centralized analyzer construction.

All analyzer instantiation is funnelled through this module so that the
CLI, API, and programmatic callers share exactly one construction path.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from .analyzers.base import BaseAnalyzer
from .scan_policy import ScanPolicy

if TYPE_CHECKING:
    from ..config.config import Config

logger = logging.getLogger(__name__)


def build_core_analyzers(
    policy: ScanPolicy,
    *,
    custom_yara_rules_path: str | Path | None = None,
    extra_rules_dirs: list[Path] | None = None,
) -> list[BaseAnalyzer]:
    """Build the default (non-optional) analyzers controlled by *policy*.

    Returns a list containing whichever of StaticAnalyzer and
    SpecComplianceAnalyzer the policy enables.
    """
    analyzers: list[BaseAnalyzer] = []

    if policy.analyzers.static:
        from .analyzers.static import StaticAnalyzer

        analyzers.append(
            StaticAnalyzer(
                custom_yara_rules_path=custom_yara_rules_path,
                policy=policy,
                extra_rules_dirs=extra_rules_dirs,
            )
        )

    if policy.analyzers.spec:
        from .analyzers.spec_analyzer import SpecComplianceAnalyzer

        analyzers.append(SpecComplianceAnalyzer())

    return analyzers


def build_analyzers(
    policy: ScanPolicy,
    *,
    config: "Config | None" = None,
    custom_yara_rules_path: str | Path | None = None,
    extra_rules_dirs: list[Path] | None = None,
    use_llm: bool = False,
    use_endpoint: bool = False,
    llm_provider: str | None = None,
    llm_max_tokens: int | None = None,
) -> list[BaseAnalyzer]:
    """Build the complete analyzer list from *policy* and feature flags.

    This is the single source of truth for analyzer construction.
    """
    analyzers = build_core_analyzers(
        policy,
        custom_yara_rules_path=custom_yara_rules_path,
        extra_rules_dirs=extra_rules_dirs,
    )

    if use_endpoint or policy.analyzers.endpoint:
        from .analyzers.endpoint_analyzer import EndpointAnalyzer

        analyzers.append(EndpointAnalyzer())

    if use_llm or policy.analyzers.llm:
        try:
            from ..config.config import Config
            from .analyzers.llm_analyzer import LLMAnalyzer

            cfg = config or Config()
            if cfg.llm_api_key:
                analyzers.append(LLMAnalyzer(cfg))
            else:
                logger.warning(
                    "LLM analyzer skipped: set A2A_SCANNER_LLM_API_KEY or enable in config."
                )
        except (ImportError, Exception) as e:
            logger.warning("Could not initialize LLM analyzer: %s", e)

    return analyzers
