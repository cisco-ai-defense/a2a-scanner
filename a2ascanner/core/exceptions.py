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

"""Domain-specific exception hierarchy for A2A Scanner core.

Re-exports the canonical base from ``a2ascanner.exceptions`` and adds
core-specific subtypes so callers can ``from a2ascanner.core.exceptions import …``.
"""

from __future__ import annotations

from a2ascanner.exceptions import A2AScannerError, ScanError  # noqa: F401


class PolicyError(A2AScannerError):
    """Raised for policy loading or validation errors."""


class RuleLoadError(A2AScannerError):
    """Raised when rules or pack manifests cannot be loaded."""
