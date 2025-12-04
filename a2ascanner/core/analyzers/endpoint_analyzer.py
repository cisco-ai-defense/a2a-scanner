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

"""Endpoint Analyzer module for A2A Scanner.

This module contains the endpoint analyzer for performing dynamic security testing
of running A2A agent endpoints. Checks for security misconfigurations, missing
security headers, and protocol compliance issues.
"""

from typing import Dict, Any, List, Optional

from .base import BaseAnalyzer, SecurityFinding
from ...utils.http_client import check_endpoint, fetch_agent_card
from ...exceptions import NetworkError, TimeoutError
from ...utils.logging_config import get_logger

logger = get_logger(__name__)


class EndpointAnalyzer(BaseAnalyzer):
    """Analyzer for A2A agent endpoints.

    Performs dynamic security testing of running agent endpoints including:
    - Availability and reachability testing
    - Agent card validation
    - Security header checks
    - HTTPS enforcement
    - CORS configuration review
    - Authentication mechanisms

    Example:
        analyzer = EndpointAnalyzer()
        findings = await analyzer.analyze("https://agent.example.com", {"timeout": 30})
    """

    def __init__(self):
        """Initialize the endpoint analyzer."""
        super().__init__("endpoint")
        self.logger.info("Endpoint analyzer initialized")

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze an A2A agent endpoint.

        Args:
            content: Endpoint URL to analyze
            context: Optional context with timeout, bearer_token, etc.

        Returns:
            List of security findings
        """
        findings = []
        context = context or {}
        endpoint_url = content.strip()

        self.logger.info(f"Analyzing endpoint: {endpoint_url}")

        # Get configuration from context
        timeout = context.get("timeout", 30.0)
        bearer_token = context.get("bearer_token")
        verify_ssl = context.get("verify_ssl", True)

        try:
            # Test endpoint
            test_results = await check_endpoint(
                endpoint_url=endpoint_url,
                timeout=timeout,
                verify_ssl=verify_ssl,
                bearer_token=bearer_token,
            )

            # Check if endpoint is reachable
            if not test_results.get("reachable"):
                findings.append(
                    self.create_security_finding(
                        severity="HIGH",
                        summary="Endpoint unreachable or not responding",
                        threat_name="ENDPOINT UNREACHABLE",
                        details={
                            "endpoint": endpoint_url,
                            "issues": test_results.get("issues", []),
                        },
                    )
                )
                return findings  # Can't proceed with further checks

            # Check HTTPS usage
            if not endpoint_url.startswith("https://"):
                findings.append(
                    self.create_security_finding(
                        severity="HIGH",
                        summary="Endpoint uses insecure HTTP protocol",
                        threat_name="INSECURE HTTP",
                        details={
                            "endpoint": endpoint_url,
                            "issue": "Agent endpoint should use HTTPS for secure communication",
                            "recommendation": "Configure endpoint to use HTTPS with valid TLS certificate",
                        },
                    )
                )

            # Check for agent card
            if not test_results.get("has_agent_card"):
                findings.append(
                    self.create_security_finding(
                        severity="MEDIUM",
                        summary="No agent card found at standard locations",
                        threat_name="MISSING AGENT CARD",
                        details={
                            "endpoint": endpoint_url,
                            "checked_locations": [
                                "/.well-known/agent-card.json",
                                "/agent-card",
                                "/agent-card.json",
                            ],
                            "recommendation": "Publish agent card at /.well-known/agent-card.json",
                        },
                    )
                )

            # Check security headers
            security_headers = test_results.get("security_headers", {})

            if not security_headers.get("X-Content-Type-Options"):
                findings.append(
                    self.create_security_finding(
                        severity="MEDIUM",
                        summary="Missing X-Content-Type-Options security header",
                        threat_name="MISSING SECURITY HEADERS",
                        details={
                            "endpoint": endpoint_url,
                            "missing_header": "X-Content-Type-Options",
                            "recommendation": "Add 'X-Content-Type-Options: nosniff' header",
                        },
                    )
                )

            if not security_headers.get("X-Frame-Options"):
                findings.append(
                    self.create_security_finding(
                        severity="MEDIUM",
                        summary="Missing X-Frame-Options security header",
                        threat_name="MISSING SECURITY HEADERS",
                        details={
                            "endpoint": endpoint_url,
                            "missing_header": "X-Frame-Options",
                            "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header",
                        },
                    )
                )

            if endpoint_url.startswith("https://") and not security_headers.get(
                "Strict-Transport-Security"
            ):
                findings.append(
                    self.create_security_finding(
                        severity="MEDIUM",
                        summary="Missing Strict-Transport-Security header (HSTS)",
                        threat_name="MISSING SECURITY HEADERS",
                        details={
                            "endpoint": endpoint_url,
                            "missing_header": "Strict-Transport-Security",
                            "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
                        },
                    )
                )

            # If agent card was found, fetch and scan it
            if test_results.get("has_agent_card"):
                agent_card_url = test_results.get("agent_card_url")
                try:
                    agent_card = await fetch_agent_card(
                        url=agent_card_url,
                        timeout=timeout,
                        verify_ssl=verify_ssl,
                        bearer_token=bearer_token,
                        allow_localhost=True,
                    )

                    # Verify agent card URL matches endpoint
                    card_url = agent_card.get("url", "").rstrip("/")
                    endpoint_base = endpoint_url.rstrip("/")

                    if card_url and card_url != endpoint_base:
                        findings.append(
                            self.create_security_finding(
                                severity="MEDIUM",
                                summary="Agent card URL does not match endpoint URL",
                                threat_name="MISSING AGENT CARD",
                                details={
                                    "endpoint_url": endpoint_url,
                                    "card_url": card_url,
                                    "recommendation": "Ensure agent card URL matches the endpoint URL",
                                },
                            )
                        )

                except Exception as e:
                    self.logger.warning(
                        f"Failed to fetch agent card for validation: {str(e)}"
                    )

            # Check if health endpoint exists
            if not test_results.get("has_health_endpoint"):
                findings.append(
                    self.create_security_finding(
                        severity="LOW",
                        summary="No health check endpoint found",
                        threat_name="ENDPOINT UNREACHABLE",
                        details={
                            "endpoint": endpoint_url,
                            "recommendation": "Implement /health or /healthz endpoint for monitoring",
                        },
                    )
                )

            # Log issues from test
            for issue in test_results.get("issues", []):
                if "security" in issue.lower() or "header" in issue.lower():
                    # Already covered above
                    continue

                self.logger.info(f"Endpoint issue: {issue}")

            # If no findings, endpoint looks good
            if not findings:
                self.logger.info(f"Endpoint appears secure: {endpoint_url}")
            else:
                self.logger.info(f"Found {len(findings)} issues with endpoint")

        except TimeoutError as e:
            findings.append(
                self.create_security_finding(
                    severity="HIGH",
                    summary=f"Endpoint request timed out: {e.message}",
                    threat_name="ENDPOINT UNREACHABLE",
                    details=e.details,
                )
            )
        except NetworkError as e:
            findings.append(
                self.create_security_finding(
                    severity="HIGH",
                    summary=f"Network error accessing endpoint: {e.message}",
                    threat_name="ENDPOINT UNREACHABLE",
                    details=e.details,
                )
            )
        except Exception as e:
            self.logger.error(f"Unexpected error analyzing endpoint: {str(e)}")
            findings.append(
                self.create_security_finding(
                    severity="MEDIUM",
                    summary=f"Error analyzing endpoint: {str(e)}",
                    threat_name="ENDPOINT UNREACHABLE",
                    details={"error": str(e), "endpoint": endpoint_url},
                )
            )

        return findings
