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

"""Tests for Endpoint Analyzer."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from a2ascanner.core.analyzers.endpoint_analyzer import EndpointAnalyzer
from a2ascanner.exceptions import NetworkError, TimeoutError


class TestEndpointAnalyzer:
    """Tests for EndpointAnalyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return EndpointAnalyzer()
    
    @pytest.mark.asyncio
    async def test_http_endpoint_flagged(self, analyzer):
        """Test HTTP endpoint is flagged as insecure."""
        # Mock test_endpoint to return basic results
        with patch("a2ascanner.core.analyzers.endpoint_analyzer.check_endpoint") as mock_test:
            mock_test.return_value = {
                "reachable": True,
                "has_agent_card": False,
                "has_health_endpoint": False,
                "security_headers": {},
                "issues": []
            }
            
            findings = await analyzer.analyze("http://example.com", {})
            
            # Should flag HTTP usage
            http_findings = [f for f in findings if "HTTP protocol" in f.summary or "insecure" in f.summary.lower()]
            assert len(http_findings) > 0
            assert any(f.severity == "HIGH" for f in http_findings)
    
    @pytest.mark.asyncio
    async def test_missing_security_headers(self, analyzer):
        """Test missing security headers are detected."""
        with patch("a2ascanner.core.analyzers.endpoint_analyzer.check_endpoint") as mock_test:
            mock_test.return_value = {
                "reachable": True,
                "has_agent_card": True,
                "has_health_endpoint": True,
                "security_headers": {},  # No security headers
                "issues": []
            }
            
            findings = await analyzer.analyze("https://example.com", {})
            
            # Should detect missing headers
            header_findings = [f for f in findings if "header" in f.summary.lower()]
            assert len(header_findings) > 0
    
    @pytest.mark.asyncio
    async def test_missing_agent_card(self, analyzer):
        """Test missing agent card is detected."""
        with patch("a2ascanner.core.analyzers.endpoint_analyzer.check_endpoint") as mock_test:
            mock_test.return_value = {
                "reachable": True,
                "has_agent_card": False,
                "has_health_endpoint": True,
                "security_headers": {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY"
                },
                "issues": []
            }
            
            findings = await analyzer.analyze("https://example.com", {})
            
            # Should detect missing agent card
            card_findings = [f for f in findings if "agent card" in f.summary.lower()]
            assert len(card_findings) > 0
    
    @pytest.mark.asyncio
    async def test_secure_endpoint_no_findings(self, analyzer):
        """Test secure endpoint with all best practices."""
        with patch("a2ascanner.core.analyzers.endpoint_analyzer.check_endpoint") as mock_test:
            mock_test.return_value = {
                "reachable": True,
                "has_agent_card": True,
                "agent_card_url": "https://example.com/.well-known/agent-card.json",
                "has_health_endpoint": True,
                "security_headers": {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Strict-Transport-Security": "max-age=31536000"
                },
                "issues": []
            }
            
            # Mock fetch_agent_card to return valid card
            with patch("a2ascanner.core.analyzers.endpoint_analyzer.fetch_agent_card") as mock_fetch:
                mock_fetch.return_value = {
                    "name": "Test Agent",
                    "url": "https://example.com"
                }
                
                findings = await analyzer.analyze("https://example.com", {})
                
                # Should have minimal or no findings
                high_findings = [f for f in findings if f.severity == "HIGH"]
                assert len(high_findings) == 0
    
    @pytest.mark.asyncio
    async def test_unreachable_endpoint(self, analyzer):
        """Test unreachable endpoint."""
        with patch("a2ascanner.core.analyzers.endpoint_analyzer.check_endpoint") as mock_test:
            mock_test.return_value = {
                "reachable": False,
                "issues": ["Failed to connect"]
            }
            
            findings = await analyzer.analyze("https://unreachable.example.com", {})
            
            # Should detect unreachable endpoint
            assert len(findings) > 0
            assert any(f.severity == "HIGH" for f in findings)
            assert any("unreachable" in f.summary.lower() for f in findings)
            unreachable = next(f for f in findings if "unreachable" in f.summary.lower())
            data = unreachable.to_dict()
            assert data["analyzer_id"] == "endpoint"
            assert data["recommendation"]
            assert "reachable" in data["recommendation"].lower() or "endpoint" in data["recommendation"].lower()
    
    @pytest.mark.asyncio
    async def test_timeout_error(self, analyzer):
        """Test timeout error handling."""
        with patch("a2ascanner.core.analyzers.endpoint_analyzer.check_endpoint") as mock_test:
            mock_test.side_effect = TimeoutError("Request timed out", {"timeout": 30})
            
            findings = await analyzer.analyze("https://slow.example.com", {})
            
            # Should create finding for timeout
            assert len(findings) > 0
            assert any("timed out" in f.summary.lower() for f in findings)
    
    @pytest.mark.asyncio
    async def test_network_error(self, analyzer):
        """Test network error handling."""
        with patch("a2ascanner.core.analyzers.endpoint_analyzer.check_endpoint") as mock_test:
            mock_test.side_effect = NetworkError("Connection failed", {"url": "https://example.com"})
            
            findings = await analyzer.analyze("https://example.com", {})
            
            # Should create finding for network error
            assert len(findings) > 0
            assert any("network error" in f.summary.lower() for f in findings)
    
    @pytest.mark.asyncio
    async def test_agent_card_url_mismatch(self, analyzer):
        """Test agent card URL mismatch detection."""
        with patch("a2ascanner.core.analyzers.endpoint_analyzer.check_endpoint") as mock_test:
            mock_test.return_value = {
                "reachable": True,
                "has_agent_card": True,
                "agent_card_url": "https://example.com/agent-card",
                "has_health_endpoint": True,
                "security_headers": {
                    "X-Content-Type-Options": "nosniff"
                },
                "issues": []
            }
            
            with patch("a2ascanner.core.analyzers.endpoint_analyzer.fetch_agent_card") as mock_fetch:
                mock_fetch.return_value = {
                    "name": "Test Agent",
                    "url": "https://different.com"  # Mismatch!
                }
                
                findings = await analyzer.analyze("https://example.com", {})
                
                # Should detect URL mismatch
                mismatch_findings = [f for f in findings if "does not match" in f.summary.lower() or "mismatch" in f.summary.lower()]
                assert len(mismatch_findings) > 0
    
    @pytest.mark.asyncio
    async def test_missing_hsts_on_https(self, analyzer):
        """Test missing HSTS on HTTPS endpoint."""
        with patch("a2ascanner.core.analyzers.endpoint_analyzer.check_endpoint") as mock_test:
            mock_test.return_value = {
                "reachable": True,
                "has_agent_card": True,
                "has_health_endpoint": True,
                "security_headers": {
                    "X-Content-Type-Options": "nosniff",
                    # Missing Strict-Transport-Security
                },
                "issues": []
            }
            
            findings = await analyzer.analyze("https://example.com", {})
            
            # Should detect missing HSTS
            hsts_findings = [f for f in findings if "hsts" in f.summary.lower() or "strict-transport-security" in f.summary.lower()]
            assert len(hsts_findings) > 0
    
    @pytest.mark.asyncio
    async def test_context_parameters(self, analyzer):
        """Test context parameters are used."""
        with patch("a2ascanner.core.analyzers.endpoint_analyzer.check_endpoint") as mock_test:
            mock_test.return_value = {
                "reachable": True,
                "has_agent_card": False,
                "has_health_endpoint": False,
                "security_headers": {},
                "issues": []
            }
            
            context = {
                "timeout": 60.0,
                "bearer_token": "test-token",
                "verify_ssl": False
            }
            
            await analyzer.analyze("https://example.com", context)
            
            # Verify test_endpoint was called with correct parameters
            call_args = mock_test.call_args
            assert call_args[1]["timeout"] == 60.0
            assert call_args[1]["bearer_token"] == "test-token"
            assert call_args[1]["verify_ssl"] is False


    @pytest.mark.asyncio
    async def test_json_findings_include_analyzer_id_and_recommendation(self, analyzer):
        """scan-endpoint JSON findings must expose analyzer_id and recommendation.

        Regression for https://github.com/cisco-ai-defense/a2a-scanner/issues/13
        """
        with patch("a2ascanner.core.analyzers.endpoint_analyzer.check_endpoint") as mock_test:
            mock_test.return_value = {
                "reachable": True,
                "has_agent_card": False,
                "has_health_endpoint": False,
                "security_headers": {},
                "issues": [],
            }

            findings = await analyzer.analyze("https://example.com", {})
            assert findings, "expected findings for incomplete endpoint"

            for finding in findings:
                data = finding.to_dict()
                assert data.get("analyzer_id") == "endpoint"
                assert data.get("analyzer") == "endpoint"
                # Endpoint analyzer supplies a concrete fix for each check
                if finding.details.get("recommendation"):
                    assert data.get("recommendation") == finding.details["recommendation"]
                    assert isinstance(data["recommendation"], str)
                    assert data["recommendation"].strip()

            # Representative cases called out in the issue
            by_summary = {f.summary: f.to_dict() for f in findings}
            header = by_summary.get("Missing X-Content-Type-Options security header")
            assert header is not None
            assert header["analyzer_id"] == "endpoint"
            assert "X-Content-Type-Options" in header["recommendation"]

            card = by_summary.get("No agent card found at standard locations")
            assert card is not None
            assert card["analyzer_id"] == "endpoint"
            assert "/.well-known/agent-card.json" in card["recommendation"]


class TestSecurityFindingAnalyzerIdMapping:
    """Unit tests for analyzer_id registry mapping used in JSON output."""

    def test_static_analyzer_maps_to_yara(self):
        from a2ascanner.core.analyzers.base import SecurityFinding

        finding = SecurityFinding(
            severity="HIGH",
            summary="test",
            threat_name="PROMPT INJECTION",
            analyzer="static_analyzer",
            details={"recommendation": "Remove injected instructions"},
        )
        data = finding.to_dict()
        assert data["analyzer_id"] == "yara"
        assert data["recommendation"] == "Remove injected instructions"

    def test_speccompliance_maps_to_spec(self):
        from a2ascanner.core.analyzers.base import SecurityFinding

        finding = SecurityFinding(
            severity="MEDIUM",
            summary="test",
            threat_name="MISSING REQUIRED FIELD",
            analyzer="speccompliance",
        )
        data = finding.to_dict()
        assert data["analyzer_id"] == "spec"
        assert data["recommendation"] is None

    def test_normalize_finding_includes_fields(self):
        from a2ascanner.core.analyzers.base import SecurityFinding
        from a2ascanner.core.results.results import ResultProcessor

        finding = SecurityFinding(
            severity="MEDIUM",
            summary="Missing X-Content-Type-Options security header",
            threat_name="MISSING SECURITY HEADERS",
            analyzer="endpoint",
            details={"recommendation": "Add 'X-Content-Type-Options: nosniff' header"},
        )
        normalized = ResultProcessor().normalize_finding(finding)
        assert normalized["analyzer_id"] == "endpoint"
        assert normalized["recommendation"] == "Add 'X-Content-Type-Options: nosniff' header"


class TestResultProcessorMergeFields:
    """Dedup merge must keep all analyzer IDs and any recommendation."""

    def test_merge_preserves_analyzer_ids_and_recommendation(self):
        from a2ascanner.core.analyzers.base import SecurityFinding
        from a2ascanner.core.results.results import ResultProcessor

        findings = [
            SecurityFinding(
                severity="MEDIUM",
                summary="Missing X-Content-Type-Options security header",
                threat_name="MISSING SECURITY HEADERS",
                analyzer="heuristic",
                details={"endpoint": "https://example.com"},
            ),
            SecurityFinding(
                severity="MEDIUM",
                summary="Missing X-Content-Type-Options security header",
                threat_name="MISSING SECURITY HEADERS",
                analyzer="endpoint",
                details={
                    "endpoint": "https://example.com",
                    "recommendation": "Add 'X-Content-Type-Options: nosniff' header",
                },
            ),
        ]
        processor = ResultProcessor(deduplicate=True)
        normalized = [processor.normalize_finding(f) for f in findings]
        merged = processor.deduplicate_findings(normalized)
        assert len(merged) == 1
        result = merged[0]
        assert result["recommendation"] == "Add 'X-Content-Type-Options: nosniff' header"
        assert "endpoint" in result["detected_by_analyzer_ids"]
        assert "heuristic" in result["detected_by_analyzer_ids"]
        assert set(result["detected_by_analyzers"]) == {"endpoint", "heuristic"}
