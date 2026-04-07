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

"""A2A Scanner Core Module

Main scanner implementation for Agent-to-Agent (A2A) protocol security analysis.
This module provides comprehensive threat detection capabilities for A2A protocol
implementations, including agent card analysis, registry scanning, and 
multi-analyzer coordination for advanced threat detection.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from pathlib import Path

import httpx

from ..config.config import Config

if TYPE_CHECKING:
    from .scan_policy import ScanPolicy
from ..utils.logging_config import get_logger, set_scan_context
from .analyzers.base import BaseAnalyzer, SecurityFinding
from .analyzers.yara_analyzer import YaraAnalyzer
from .analyzers.heuristic_analyzer import HeuristicAnalyzer
from .analyzers.llm_analyzer import LLMAnalyzer
from .analyzers.endpoint_analyzer import EndpointAnalyzer
from .analyzers.spec_analyzer import SpecComplianceAnalyzer
from .analyzers.meta_analyzer import LLMMetaAnalyzer, MetaAnalysisResult
from .models import ScanResult

logger = get_logger(__name__)


class Scanner:
    """Main scanner class for A2A security threat detection.

    Coordinates multiple analyzers to scan agent cards, registries,
    and other A2A protocol components for security threats.
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        custom_analyzers: Optional[List[BaseAnalyzer]] = None,
        rules_dir: Optional[str] = None,
        enable_meta_analysis: bool = False,
        policy: Optional["ScanPolicy"] = None,
        analyzers: Optional[List[BaseAnalyzer]] = None,
    ):
        """Initialize the A2A scanner.

        Args:
            config: Configuration object. If None, creates default config.
            custom_analyzers: Optional list of custom analyzer instances.
            rules_dir: Optional custom path to YARA rules directory.
            enable_meta_analysis: Whether to enable LLM meta-analysis by default.
            policy: Optional scan policy; disabled rules and severity overrides apply
                to findings returned from analyzer runs.
            analyzers: Optional pre-built analyzer instances; when set, replaces
                default YARA/heuristic/spec construction while preserving meta setup.
        """
        self.config = config or Config()
        self.policy = policy
        self.custom_analyzers = custom_analyzers or []
        self.enable_meta_analysis = enable_meta_analysis
        self.meta_analyzer: Optional[LLMMetaAnalyzer] = None

        if analyzers is not None:
            self.analyzers = {}
            self._register_analyzer_instances(analyzers)
            if self.enable_meta_analysis and self.config.llm_api_key:
                try:
                    self.meta_analyzer = LLMMetaAnalyzer(self.config)
                    logger.info("LLM Meta-Analyzer initialized")
                except Exception as e:
                    logger.warning(f"Failed to initialize LLM Meta-Analyzer: {e}")
        else:
            # Initialize analyzers
            self._init_analyzers(rules_dir)

        logger.info("A2A Scanner initialized")

    @staticmethod
    def _analyzer_registry_key(analyzer: BaseAnalyzer) -> str:
        """Map analyzer display names to registry keys used by scan routing."""
        key = analyzer.name.lower()
        if key == "speccompliance":
            return "spec"
        if key == "static_analyzer":
            return "yara"
        return key

    def _register_analyzer_instances(self, instances: List[BaseAnalyzer]) -> None:
        """Populate ``self.analyzers`` from pre-built instances."""
        for analyzer in instances:
            self.analyzers[self._analyzer_registry_key(analyzer)] = analyzer
        for analyzer in self.custom_analyzers:
            self.analyzers[self._analyzer_registry_key(analyzer)] = analyzer

    def _init_analyzers(self, rules_dir: Optional[str] = None):
        """Initialize analyzers via the analyzer factory for consistent behavior."""
        from .analyzer_factory import build_core_analyzers
        from .scan_policy import ScanPolicy

        self.analyzers: Dict[str, BaseAnalyzer] = {}

        policy = self.policy or ScanPolicy.default()

        try:
            core = build_core_analyzers(
                policy,
                custom_yara_rules_path=rules_dir,
            )
            for analyzer in core:
                self.analyzers[self._analyzer_registry_key(analyzer)] = analyzer
        except Exception as e:
            logger.warning("Failed to build core analyzers via factory: %s", e)
            # Fallback to legacy YARA-only
            try:
                self.analyzers["yara"] = YaraAnalyzer(rules_dir=rules_dir)
            except Exception as exc:
                logger.warning("Failed to initialize YARA analyzer: %s", exc)

        # Always add heuristic if not already present
        if "heuristic" not in self.analyzers:
            try:
                self.analyzers["heuristic"] = HeuristicAnalyzer()
            except Exception as e:
                logger.warning("Failed to initialize Heuristic analyzer: %s", e)

        # Add endpoint analyzer
        if "endpoint" not in self.analyzers:
            try:
                self.analyzers["endpoint"] = EndpointAnalyzer()
            except Exception as e:
                logger.warning("Failed to initialize Endpoint analyzer: %s", e)

        # Add spec if not already present (factory includes it when policy.analyzers.spec)
        if "spec" not in self.analyzers:
            try:
                self.analyzers["spec"] = SpecComplianceAnalyzer()
            except Exception as e:
                logger.warning("Failed to initialize Spec analyzer: %s", e)

        # Initialize LLM analyzer if API key is configured
        if self.config.llm_api_key:
            try:
                self.analyzers["llm"] = LLMAnalyzer(self.config)
            except Exception as e:
                logger.warning("Failed to initialize LLM analyzer: %s", e)

            if self.enable_meta_analysis:
                try:
                    self.meta_analyzer = LLMMetaAnalyzer(self.config)
                except Exception as e:
                    logger.warning("Failed to initialize LLM Meta-Analyzer: %s", e)

        # Add custom analyzers
        for analyzer in self.custom_analyzers:
            self.analyzers[analyzer.name.lower()] = analyzer

    async def scan_agent_card(
        self,
        card: Dict[str, Any],
        analyzers: Optional[List[str]] = None,
    ) -> ScanResult:
        """Scan an agent card for security threats.

        Args:
            card: Agent card data (dict with id, name, url, description, etc.)
            analyzers: Optional list of analyzer names to use. If None, uses all.

        Returns:
            ScanResult with findings from all analyzers.
        """
        card_name = card.get("name", card.get("id", "unknown"))
        logger.info(f"Scanning agent card: {card_name}")

        # Convert card to JSON string for analysis
        card_json = json.dumps(card, indent=2)

        # Prepare context
        context = {
            "target_type": "agent_card",
            "agent_id": card.get("id"),
            "agent_name": card.get("name"),
        }

        # Exclude endpoint analyzer for agent card scanning
        # (endpoint analyzer is for live endpoint testing, not static cards)
        if analyzers is None:
            analyzer_list = [
                name for name in self.analyzers if name != "endpoint"
            ]
        else:
            analyzer_list = [name for name in analyzers if name != "endpoint"]

        # Run analyzers
        findings = await self._run_analyzers(
            content=card_json,
            context=context,
            analyzers=analyzer_list,
        )

        # Run specialized agent card analysis with heuristic analyzer
        if "heuristic" in self.analyzers:
            try:
                heuristic_analyzer = self.analyzers["heuristic"]
                card_findings = await heuristic_analyzer.analyze_agent_card(card)
                findings.extend(card_findings)
            except Exception as e:
                logger.error(f"Heuristic analyzer agent card analysis failed: {e}")

        # Create scan result
        result = ScanResult(
            target_name=card_name,
            target_type="agent_card",
            status="completed",
            analyzers=analyzer_list,  # Use actual analyzers that ran
            findings=findings,
            metadata={"agent_id": card.get("id"), "url": card.get("url")},
        )

        logger.info(
            f"Agent card scan complete: {card_name}, " f"findings={len(findings)}"
        )

        return result

    async def scan_registry(
        self,
        registry_url: str,
        analyzers: Optional[List[str]] = None,
    ) -> ScanResult:
        """Scan an agent registry for security threats.

        Args:
            registry_url: URL of the agent registry (e.g., /.well-known/agents)
            analyzers: Optional list of analyzer names to use.

        Returns:
            ScanResult with findings from registry analysis.
        """
        logger.info(f"Scanning agent registry: {registry_url}")

        try:
            # Fetch registry data
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.get(registry_url)
                response.raise_for_status()
                registry_data = response.json()

            # Analyze registry structure
            findings = []

            # Check for mass registration
            if isinstance(registry_data, list) and len(registry_data) > 50:
                findings.append(
                    SecurityFinding(
                        severity="MEDIUM",
                        summary=f"Large number of agents in registry: {len(registry_data)}",
                        threat_name="Discovery Poisoning - Mass Registration",
                        analyzer="Registry",
                        details={"agent_count": len(registry_data)},
                    )
                )

            # Scan each agent card in registry
            if isinstance(registry_data, list):
                for card in registry_data:
                    if isinstance(card, dict):
                        card_result = await self.scan_agent_card(card, analyzers)
                        findings.extend(card_result.findings)

            # Determine which analyzers were used
            analyzer_list = analyzers if analyzers else list(self.analyzers)

            result = ScanResult(
                target_name=registry_url,
                target_type="agent_registry",
                status="completed",
                analyzers=analyzer_list,
                findings=findings,
                metadata={
                    "url": registry_url,
                    "agent_count": (
                        len(registry_data) if isinstance(registry_data, list) else 0
                    ),
                },
            )

            logger.info(
                f"Registry scan complete: {registry_url}, " f"findings={len(findings)}"
            )

            return result

        except Exception as e:
            logger.error(f"Registry scan failed: {e}")
            return ScanResult(
                target_name=registry_url,
                target_type="agent_registry",
                status="failed",
                analyzers=[],
                findings=[],
                metadata={"error": str(e)},
            )

    async def scan_endpoint(
        self,
        endpoint_url: str,
        analyzers: Optional[List[str]] = None,
        timeout: float = 30.0,
        bearer_token: Optional[str] = None,
        verify_ssl: bool = True,
    ) -> ScanResult:
        """Scan an A2A agent endpoint for security issues.

        Args:
            endpoint_url: URL of the agent endpoint to scan
            analyzers: Optional list of analyzer names to use
            timeout: Request timeout in seconds
            bearer_token: Optional bearer token for authentication
            verify_ssl: Whether to verify SSL certificates

        Returns:
            ScanResult with findings from endpoint analysis
        """
        logger.info(f"Scanning endpoint: {endpoint_url}")

        # Set scan context for logging
        set_scan_context(
            {"scan_type": "endpoint", "endpoint_url": endpoint_url, "timeout": timeout}
        )

        # Prepare context for analyzers
        context = {
            "target_type": "endpoint",
            "endpoint_url": endpoint_url,
            "timeout": timeout,
            "bearer_token": bearer_token,
            "verify_ssl": verify_ssl
            and not self.config.dev_mode,  # Override if dev mode
        }

        # Use endpoint analyzer specifically or all analyzers
        if analyzers is None:
            analyzers = ["endpoint"]
        elif "endpoint" not in analyzers:
            analyzers.append("endpoint")

        # Run analyzers
        findings = await self._run_analyzers(
            content=endpoint_url, context=context, analyzers=analyzers
        )

        result = ScanResult(
            target_name=endpoint_url,
            target_type="endpoint",
            status="completed",
            analyzers=analyzers,
            findings=findings,
            metadata={
                "endpoint_url": endpoint_url,
                "timeout": timeout,
                "verify_ssl": verify_ssl,
            },
        )

        logger.info(f"Endpoint scan complete: {endpoint_url}, findings={len(findings)}")

        return result

    async def scan_file(
        self,
        file_path: str,
        analyzers: Optional[List[str]] = None,
    ) -> ScanResult:
        """Scan a file containing A2A protocol data.

        Args:
            file_path: Path to file to scan
            analyzers: Optional list of analyzer names to use.

        Returns:
            ScanResult with findings.
        """
        logger.info(f"Scanning file: {file_path}")

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Read file content
        content = path.read_text()

        # Determine file type and scan accordingly
        if path.suffix in [".json", ".js"]:
            try:
                data = json.loads(content)
                if isinstance(data, dict) and any(
                    k in data for k in ["id", "name", "url"]
                ):
                    # Looks like an agent card
                    return await self.scan_agent_card(data, analyzers)
                elif isinstance(data, list):
                    # Might be a registry
                    findings = []
                    for item in data:
                        if isinstance(item, dict):
                            result = await self.scan_agent_card(item, analyzers)
                            findings.extend(result.findings)
                    
                    # Determine which analyzers were used
                    analyzer_list = analyzers if analyzers else list(self.analyzers)
                    
                    return ScanResult(
                        target_name=path.name,
                        target_type="file",
                        status="completed",
                        analyzers=analyzer_list,
                        findings=findings,
                        metadata={"file_path": file_path},
                    )
            except json.JSONDecodeError:
                pass

        # Default: scan as generic content
        # Exclude analyzers not suitable for source code files
        if analyzers is None:
            # Endpoint analyzer is for live URLs only
            # Spec analyzer is for JSON agent cards only  
            exclude_analyzers = ["endpoint"]
            
            # Don't run spec analyzer on source code files (py, js, ts, etc.)
            if path.suffix in [".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java"]:
                exclude_analyzers.append("spec")
            
            analyzer_list = [name for name in self.analyzers if name not in exclude_analyzers]
        else:
            analyzer_list = [name for name in analyzers if name not in ["endpoint"]]
            
        context = {
            "target_type": "file",
            "file_path": file_path,
            "file_name": path.name,
            "file_extension": path.suffix,
        }
        findings = await self._run_analyzers(content, context, analyzer_list)

        return ScanResult(
            target_name=path.name,
            target_type="file",
            status="completed",
            analyzers=analyzer_list,
            findings=findings,
            metadata=context,
        )

    @staticmethod
    def _finding_rule_id(finding: SecurityFinding) -> str:
        """Resolve policy rule id for a finding (details rule_id, else threat name)."""
        rid = (finding.details or {}).get("rule_id")
        if rid:
            return str(rid)
        return finding.threat_name

    def _build_enrichment(self, findings: List[SecurityFinding]) -> str:
        """Summarize Phase 1 findings for LLM enrichment context."""
        lines: List[str] = []
        for i, f in enumerate(findings, 1):
            lines.append(
                f"{i}. [{f.severity}] {f.threat_name}: {f.summary} (analyzer={f.analyzer})"
            )
        return "\n".join(lines)

    def _apply_policy(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Filter by disabled rules and apply severity overrides from policy."""
        if not self.policy:
            return findings
        out: List[SecurityFinding] = []
        for f in findings:
            rule_id = self._finding_rule_id(f)
            if not self.policy.is_rule_enabled(rule_id):
                continue
            eff = self.policy.get_effective_severity(rule_id, f.severity)
            if eff != f.severity:
                f.severity = eff
            out.append(f)
        return out

    def _deduplicate(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Drop duplicate findings respecting policy.finding_output flags."""
        fo = getattr(self.policy, "finding_output", None) if self.policy else None

        if fo and not fo.dedupe_exact_findings:
            return findings

        seen: set[tuple[str, str]] = set()
        out: List[SecurityFinding] = []
        for f in findings:
            key = (f.threat_name, f.summary)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def _annotate_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Add policy fingerprint and co-occurrence metadata when enabled."""
        if not self.policy:
            return findings
        fo = self.policy.finding_output

        if fo.attach_policy_fingerprint:
            import hashlib

            policy_fp = hashlib.sha256(
                f"{self.policy.policy_name}:{self.policy.policy_version}:{sorted(self.policy.disabled_rules)}".encode()
            ).hexdigest()[:12]
            for f in findings:
                if isinstance(f.details, dict):
                    f.details["policy_fingerprint"] = policy_fp

        if fo.annotate_same_path_rule_cooccurrence:
            from collections import Counter

            rule_ids = [self._finding_rule_id(f) for f in findings]
            counts = Counter(rule_ids)
            for f in findings:
                rid = self._finding_rule_id(f)
                if counts[rid] > 1 and isinstance(f.details, dict):
                    f.details["same_rule_count"] = counts[rid]

        return findings

    async def _run_analyzers(
        self,
        content: str,
        context: Dict[str, Any],
        analyzers: Optional[List[str]] = None,
    ) -> List[SecurityFinding]:
        """Run analyzers in two phases: non-LLM concurrently, then LLM with enrichment.

        Args:
            content: Content to analyze
            context: Analysis context
            analyzers: Optional list of analyzer registry keys. If None, uses all.

        Returns:
            Findings after policy filtering and deduplication.
        """
        keys = list(analyzers) if analyzers is not None else list(self.analyzers.keys())
        selected = [self.analyzers[k] for k in keys if k in self.analyzers]

        phase1 = [a for a in selected if a.name.lower() != "llm"]
        phase1_results = await asyncio.gather(
            *[a.analyze(content, context) for a in phase1],
            return_exceptions=True,
        )

        findings: List[SecurityFinding] = []
        for result in phase1_results:
            if isinstance(result, Exception):
                logger.error("Analyzer failed: %s", result)
                continue
            if isinstance(result, list):
                findings.extend(result)

        llm_analyzers = [a for a in selected if a.name.lower() == "llm"]
        if llm_analyzers:
            enrichment = self._build_enrichment(findings) if findings else ""
            for analyzer in llm_analyzers:
                if findings and hasattr(analyzer, "set_enrichment_context"):
                    analyzer.set_enrichment_context(enrichment)
                try:
                    llm_findings = await analyzer.analyze(content, context)
                    findings.extend(llm_findings)
                except Exception as e:
                    logger.warning("LLM analysis failed: %s", e)

        findings = self._apply_policy(findings)
        findings = self._deduplicate(findings)
        findings = self._annotate_findings(findings)

        return findings

    def get_available_analyzers(self) -> List[str]:
        """Get list of available analyzer names.

        Returns:
            List of analyzer names.
        """
        return list(self.analyzers.keys())

    async def run_meta_analysis(
        self,
        scan_result: ScanResult,
        original_content: Optional[str] = None,
    ) -> MetaAnalysisResult:
        """Run LLM meta-analysis on scan findings.

        This performs a second-pass analysis using an LLM to:
        - Identify and prune false positives
        - Prioritize findings by actual risk
        - Correlate related findings
        - Provide specific recommendations and fixes

        Args:
            scan_result: The scan result containing findings to analyze
            original_content: Optional original scanned content for context

        Returns:
            MetaAnalysisResult with validated findings and recommendations

        Raises:
            ValueError: If meta-analyzer is not initialized
        """
        if not self.meta_analyzer:
            # Try to initialize on-demand if LLM API key is available
            if self.config.llm_api_key:
                try:
                    self.meta_analyzer = LLMMetaAnalyzer(self.config)
                    logger.info("LLM Meta-Analyzer initialized on-demand")
                except Exception as e:
                    raise ValueError(
                        f"Failed to initialize LLM Meta-Analyzer: {e}. "
                        "Ensure LLM API key is configured."
                    )
            else:
                raise ValueError(
                    "LLM Meta-Analyzer not available. "
                    "Configure A2A_SCANNER_LLM_API_KEY to enable meta-analysis."
                )

        if not scan_result.findings:
            logger.info("No findings to meta-analyze")
            return MetaAnalysisResult(
                overall_risk_assessment={
                    "risk_level": "SAFE",
                    "summary": "No security findings to analyze",
                }
            )

        context = {
            "target_name": scan_result.target_name,
            "target_type": scan_result.target_type,
            "metadata": scan_result.metadata,
        }

        # Use original content if provided, otherwise try to get from metadata
        content = original_content or ""
        if not content and scan_result.metadata:
            content = scan_result.metadata.get("content", "")

        logger.info(
            f"Running meta-analysis on {len(scan_result.findings)} findings "
            f"from {scan_result.target_name}"
        )

        return await self.meta_analyzer.analyze_findings(
            findings=scan_result.findings,
            original_content=content,
            context=context,
        )

    async def scan_with_meta_analysis(
        self,
        card: Dict[str, Any],
        analyzers: Optional[List[str]] = None,
    ) -> tuple[ScanResult, MetaAnalysisResult]:
        """Scan an agent card and run meta-analysis on findings.

        This is a convenience method that combines scanning with meta-analysis
        in a single call.

        Args:
            card: Agent card data to scan
            analyzers: Optional list of analyzer names to use

        Returns:
            Tuple of (ScanResult, MetaAnalysisResult)
        """
        # Run the initial scan
        scan_result = await self.scan_agent_card(card, analyzers)

        # Run meta-analysis on findings
        card_json = json.dumps(card, indent=2)
        meta_result = await self.run_meta_analysis(scan_result, card_json)

        return scan_result, meta_result

    def apply_meta_analysis(
        self,
        scan_result: ScanResult,
        meta_result: MetaAnalysisResult,
        remove_false_positives: bool = True,
    ) -> ScanResult:
        """Apply meta-analysis results to a scan result.

        Creates a new ScanResult with findings filtered and enriched
        based on meta-analysis. The output format is consistent with
        standard ScanResult format for seamless integration.

        Args:
            scan_result: Original scan result
            meta_result: Meta-analysis result to apply
            remove_false_positives: Whether to remove identified false positives

        Returns:
            New ScanResult with applied meta-analysis, using consistent SecurityFinding format
        """
        # Use the MetaAnalysisResult helper to get consistent SecurityFinding objects
        new_findings = meta_result.get_findings_as_security_findings()

        # Create new scan result with enriched findings
        # Format matches standard ScanResult.to_dict() output
        new_result = ScanResult(
            target_name=scan_result.target_name,
            target_type=scan_result.target_type,
            status=scan_result.status,
            analyzers=scan_result.analyzers + ["meta"],
            findings=new_findings,
            metadata={
                **scan_result.metadata,
                "meta_analysis": {
                    "applied": True,
                    "false_positives_removed": len(meta_result.false_positives),
                    "original_finding_count": len(scan_result.findings),
                    "validated_finding_count": len(new_findings),
                    "recommendations_count": len(meta_result.recommendations),
                    "risk_assessment": meta_result.overall_risk_assessment,
                    "correlations": meta_result.correlations,
                    "recommendations": meta_result.recommendations,
                },
            },
        )

        return new_result
