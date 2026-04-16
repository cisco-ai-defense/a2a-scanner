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

"""SARIF 2.1.0 report generation for GitHub Code Scanning and compatible tools."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import quote

import a2ascanner

from ..models import ScanResult


def _severity_to_sarif_level(severity: str) -> str:
    s = (severity or "").upper()
    if s in ("HIGH", "CRITICAL"):
        return "error"
    if s == "MEDIUM":
        return "warning"
    if s == "LOW":
        return "note"
    return "note"


def _artifact_uri_for_target(target_name: str) -> str:
    """Synthetic URI when findings have no file path (A2A scan target)."""
    safe = quote(target_name or "unknown", safe="/:@")
    return f"a2a-scan://target/{safe}"


class SARIFReporter:
    """Emit SARIF 2.1.0 with tool driver ``a2a-scanner``."""

    def __init__(self, pretty: bool = True) -> None:
        self.pretty = pretty

    def generate_report(self, data: ScanResult) -> str:
        """Build SARIF document from a ``ScanResult``."""
        run_uuid = str(uuid.uuid4())
        utc_now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        artifact_uri = _artifact_uri_for_target(data.target_name)

        rules_by_id: Dict[str, Dict[str, Any]] = {}
        rule_index_by_id: Dict[str, int] = {}
        results: List[Dict[str, Any]] = []

        for finding in data.findings:
            fd = finding.to_dict() if hasattr(finding, "to_dict") else finding
            threat = str(fd.get("threat_name", "finding"))
            analyzer = str(fd.get("analyzer", "unknown"))
            rule_id = f"{analyzer}/{threat}".replace(" ", "_")

            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": threat,
                    "shortDescription": {"text": threat},
                    "fullDescription": {
                        "text": fd.get("description") or fd.get("summary") or threat
                    },
                    "properties": {"tags": ["security", "a2a", analyzer]},
                }
                rule_index_by_id[rule_id] = len(rule_index_by_id)

            rule_index = rule_index_by_id[rule_id]
            severity = str(fd.get("severity", "UNKNOWN"))
            level = _severity_to_sarif_level(severity)
            summary = str(fd.get("summary", ""))
            message_text = summary or threat

            result: Dict[str, Any] = {
                "ruleId": rule_id,
                "ruleIndex": rule_index,
                "level": level,
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                        },
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": f"{data.target_name}::{analyzer}::{threat}",
                                "name": threat,
                            }
                        ],
                    }
                ],
                "properties": {
                    "severity": severity,
                    "analyzer": analyzer,
                    "threat_name": threat,
                    "details": fd.get("details", {}),
                },
            }
            results.append(result)

        rule_list = sorted(rules_by_id.values(), key=lambda r: rule_index_by_id[r["id"]])

        sarif: Dict[str, Any] = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "a2a-scanner",
                            "informationUri": "https://github.com/cisco-ai-defense/a2a-scanner",
                            "version": a2ascanner.__version__,
                            "rules": rule_list,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": utc_now,
                        }
                    ],
                    "results": results,
                    "columnKind": "utf16CodeUnits",
                    "properties": {
                        "runGuid": run_uuid,
                        "targetName": data.target_name,
                        "targetType": data.target_type,
                        "status": data.status,
                    },
                }
            ],
        }

        if self.pretty:
            return json.dumps(sarif, indent=2, default=str, ensure_ascii=False)
        return json.dumps(sarif, default=str, ensure_ascii=False)

    def save_report(self, data, output_path) -> None:
        """Generate report and write to *output_path*."""
        from pathlib import Path as _P

        _P(output_path).write_text(self.generate_report(data), encoding="utf-8")
