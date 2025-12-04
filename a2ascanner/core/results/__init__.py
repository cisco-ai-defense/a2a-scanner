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

"""Results module exports for A2A Scanner.

This module provides access to result normalization, aggregation, formatting,
statistics, and risk assessment functionality for comprehensive security reporting.
"""

from .results import ResultProcessor, RESULT_PROCESSOR
from .formatters import OutputMode, ResultFormatter
from .statistics import StatisticsCalculator
from .risk_assessor import RiskAssessor

__all__ = [
    "ResultProcessor",
    "RESULT_PROCESSOR",
    "OutputMode",
    "ResultFormatter",
    "StatisticsCalculator",
    "RiskAssessor",
]
