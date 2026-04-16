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

"""JSON report generation for scan results."""

from __future__ import annotations

import json
from typing import Any


class JSONReporter:
    """Serialize a scan result (or any object with ``to_dict()``) to JSON."""

    def __init__(self, pretty: bool = True) -> None:
        self.pretty = pretty

    def generate_report(self, data: Any) -> str:
        """Return JSON string for ``data.to_dict()``."""
        report_dict = data.to_dict()
        if self.pretty:
            return json.dumps(report_dict, indent=2, default=str)
        return json.dumps(report_dict, default=str)

    def save_report(self, data, output_path) -> None:
        """Generate report and write to *output_path*."""
        from pathlib import Path as _P

        _P(output_path).write_text(self.generate_report(data), encoding="utf-8")
