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

"""A2A Scanner data package — rule packs, policies, and prompt assets."""

from __future__ import annotations

from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent

_PACKS_DIR = DATA_DIR / "packs"


def resolve_rule_packs(names: list[str]) -> list[Path]:
    """Map pack names to their ``signatures/`` directories.

    Raises ValueError for unknown packs or packs without signatures.
    """
    dirs: list[Path] = []
    for name in names:
        name = name.strip().lower()
        if name == "core":
            continue
        sigs_dir = _PACKS_DIR / name / "signatures"
        if not sigs_dir.is_dir():
            raise ValueError(f"Rule pack '{name}' has no signatures/ directory")
        dirs.append(sigs_dir)
    return dirs


def list_available_packs() -> list[str]:
    """Return names of non-core packs that have a ``signatures/`` dir."""
    packs: list[str] = []
    if not _PACKS_DIR.is_dir():
        return packs
    for child in sorted(_PACKS_DIR.iterdir()):
        if child.is_dir() and child.name != "core" and (child / "signatures").is_dir():
            packs.append(child.name)
    return packs
