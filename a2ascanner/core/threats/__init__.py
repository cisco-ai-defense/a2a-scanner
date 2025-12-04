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

"""Threats module exports for A2A Scanner.

This module provides centralized threat taxonomy for the A2A Scanner with unified
threat classifications, definitions, and mappings from analyzer outputs to
standardized A2A threat taxonomy with AI Security Taxonomy classifications.
"""

from .threats import (
    ThreatMapping,
    YARA_THREAT_MAPPING,
    HEURISTIC_THREAT_MAPPING,
    LLM_THREAT_MAPPING,
    SSE_THREAT_MAPPING,
    ENDPOINT_THREAT_MAPPING,
    get_threat_info,
    get_threat_severity,
    normalize_threat_category,
)

__all__ = [
    "ThreatMapping",
    "YARA_THREAT_MAPPING",
    "HEURISTIC_THREAT_MAPPING",
    "LLM_THREAT_MAPPING",
    "SSE_THREAT_MAPPING",
    "ENDPOINT_THREAT_MAPPING",
    "get_threat_info",
    "get_threat_severity",
    "normalize_threat_category",
]
