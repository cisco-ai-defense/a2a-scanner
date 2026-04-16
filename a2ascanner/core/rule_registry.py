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

"""Pack manifests (``pack.yaml``) and a registry for rule enablement and metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import yaml

from ..data import DATA_DIR


@dataclass
class RuleDefinition:
    id: str
    enabled: bool = True
    severity: str = "MEDIUM"
    description: str = ""


@dataclass
class RulePack:
    name: str
    version: str
    description: str
    rules: dict[str, RuleDefinition] = field(default_factory=dict)


class PackLoader:
    """Load rule packs from ``pack.yaml`` beside pack assets."""

    @staticmethod
    def load_pack(pack_dir: Path) -> RulePack:
        """Load a pack from pack.yaml in the given directory."""
        pack_dir = Path(pack_dir)
        manifest = pack_dir / "pack.yaml"
        if not manifest.is_file():
            raise FileNotFoundError(f"No pack.yaml in {pack_dir}")

        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"Invalid pack.yaml (expected mapping): {manifest}")

        pack_info = data.get("pack") or {}
        if not isinstance(pack_info, dict):
            raise ValueError(f"Invalid pack.yaml: missing or invalid 'pack' section in {manifest}")

        name = str(pack_info.get("name", pack_dir.name))
        version = str(pack_info.get("version", "0.0.0"))
        description = str(pack_info.get("description", ""))

        rules_raw = data.get("rules") or {}
        if not isinstance(rules_raw, dict):
            rules_raw = {}

        rules: dict[str, RuleDefinition] = {}
        for rule_id, cfg in rules_raw.items():
            rid = str(rule_id)
            if isinstance(cfg, dict):
                rules[rid] = RuleDefinition(
                    id=rid,
                    enabled=bool(cfg.get("enabled", True)),
                    severity=str(cfg.get("severity", "MEDIUM")),
                    description=str(cfg.get("description", "")),
                )
            else:
                rules[rid] = RuleDefinition(id=rid)

        return RulePack(name=name, version=version, description=description, rules=rules)

    @staticmethod
    def discover_packs(extra_dirs: list[Path] | None = None) -> dict[str, RulePack]:
        """Discover all packs (built-in under data/packs, then optional extra roots).

        Later roots override packs with the same name as earlier roots.
        """
        packs: dict[str, RulePack] = {}
        roots: list[Path] = [DATA_DIR / "packs"]
        if extra_dirs:
            roots.extend(Path(p).resolve() for p in extra_dirs)

        for root in roots:
            if not root.is_dir():
                continue
            for child in sorted(root.iterdir()):
                if not child.is_dir():
                    continue
                if not (child / "pack.yaml").is_file():
                    continue
                pack = PackLoader.load_pack(child)
                packs[pack.name] = pack
        return packs


class RuleRegistry:
    """Aggregates ``RulePack`` instances and resolves rule definitions by id."""

    def __init__(self) -> None:
        self.packs: dict[str, RulePack] = {}

    def register_pack(self, pack: RulePack) -> None:
        self.packs[pack.name] = pack

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Return pack ``enabled`` flag for ``rule_id`` if known; otherwise True."""
        r = self.get_rule(rule_id)
        if r is None:
            return True
        return r.enabled

    def get_rule(self, rule_id: str) -> RuleDefinition | None:
        """Return the first matching rule definition (packs ordered by name)."""
        for pack_name in sorted(self.packs):
            r = self.packs[pack_name].rules.get(rule_id)
            if r is not None:
                return r
        return None
