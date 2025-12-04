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

"""HTTP client utilities for A2A Scanner.

This module provides HTTP client functionality for fetching agent cards,
scanning endpoints, and making network requests with security controls.
"""

import httpx
from typing import Optional, Dict, Any
from urllib.parse import urljoin

from ..exceptions import (
    NetworkError,
    TimeoutError,
    ValidationError,
    SSRFError,
    AuthenticationError,
)
from ..utils.validators import validate_url, validate_agent_card
from ..utils.logging_config import get_logger

logger = get_logger(__name__)

# Default timeout for HTTP requests (in seconds)
DEFAULT_TIMEOUT = 30.0

# Maximum response size (10MB)
MAX_RESPONSE_SIZE = 10 * 1024 * 1024

# User agent string
USER_AGENT = "A2A-Scanner/1.0.0 (Security Scanner)"


async def fetch_agent_card(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    bearer_token: Optional[str] = None,
    allow_localhost: bool = False,
    allow_private_ips: bool = False,
) -> Dict[str, Any]:
    """Fetch and validate an agent card from a URL.

    Args:
        url: URL to fetch agent card from
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        bearer_token: Optional bearer token for authentication
        allow_localhost: Whether to allow localhost URLs
        allow_private_ips: Whether to allow private IP addresses

    Returns:
        Validated agent card dictionary

    Raises:
        NetworkError: If network request fails
        TimeoutError: If request times out
        ValidationError: If agent card is invalid
        SSRFError: If URL is blocked by SSRF protection
    """
    # Validate URL first
    try:
        url = validate_url(
            url, allow_localhost=allow_localhost, allow_private_ips=allow_private_ips
        )
    except (ValidationError, SSRFError) as e:
        logger.error(f"URL validation failed: {e.message}", extra={"url": url})
        raise

    logger.info(f"Fetching agent card from: {url}")

    # Prepare headers
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}

    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    # Make request
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=verify_ssl, follow_redirects=True, max_redirects=5
        ) as client:
            response = await client.get(url, headers=headers)

            # Check response status
            if response.status_code == 401:
                raise AuthenticationError(
                    "Authentication required", {"url": url, "status_code": 401}
                )
            if response.status_code == 403:
                raise AuthenticationError(
                    "Access forbidden", {"url": url, "status_code": 403}
                )
            if response.status_code == 404:
                raise NetworkError(
                    "Agent card not found", {"url": url, "status_code": 404}
                )
            if response.status_code >= 400:
                raise NetworkError(
                    f"HTTP error {response.status_code}",
                    {"url": url, "status_code": response.status_code},
                )

            # Check content type
            content_type = response.headers.get("content-type", "")
            if "application/json" not in content_type:
                logger.warning(
                    f"Unexpected content type: {content_type}",
                    extra={"url": url, "content_type": content_type},
                )

            # Check response size
            content_length = len(response.content)
            if content_length > MAX_RESPONSE_SIZE:
                raise ValidationError(
                    "Response too large",
                    {"size": content_length, "max": MAX_RESPONSE_SIZE},
                )

            # Parse JSON
            try:
                agent_card = response.json()
            except Exception as e:
                raise ValidationError(
                    f"Failed to parse JSON response: {str(e)}", {"url": url}
                )

            # Validate agent card schema
            agent_card = validate_agent_card(agent_card)

            logger.info(
                f"Successfully fetched agent card: {agent_card.get('name')}",
                extra={"url": url, "agent_name": agent_card.get("name")},
            )

            return agent_card

    except httpx.TimeoutException:
        raise TimeoutError(
            f"Request timed out after {timeout}s", {"url": url, "timeout": timeout}
        )
    except httpx.ConnectError as e:
        raise NetworkError(
            f"Connection failed: {str(e)}", {"url": url, "error": str(e)}
        )
    except httpx.HTTPStatusError as e:
        raise NetworkError(
            f"HTTP error: {str(e)}", {"url": url, "status_code": e.response.status_code}
        )
    except (ValidationError, SSRFError, AuthenticationError):
        # Re-raise our custom exceptions
        raise
    except Exception as e:
        raise NetworkError(
            f"Unexpected error fetching agent card: {str(e)}",
            {"url": url, "error": str(e)},
        )


async def check_endpoint(
    endpoint_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    bearer_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Test an A2A agent endpoint for availability and security.

    Args:
        endpoint_url: Base URL of the agent endpoint
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        bearer_token: Optional bearer token for authentication

    Returns:
        Dictionary with test results

    Raises:
        NetworkError: If endpoint cannot be reached
    """
    # Validate URL
    try:
        endpoint_url = validate_url(
            endpoint_url, allow_localhost=True, allow_private_ips=False
        )
    except (ValidationError, SSRFError) as e:
        logger.error(f"Endpoint URL validation failed: {e.message}")
        raise

    logger.info(f"Testing endpoint: {endpoint_url}")

    results = {
        "endpoint_url": endpoint_url,
        "reachable": False,
        "has_agent_card": False,
        "has_health_endpoint": False,
        "security_headers": {},
        "issues": [],
    }

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}

    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=verify_ssl, follow_redirects=True
        ) as client:
            # Test base endpoint
            try:
                response = await client.get(endpoint_url, headers=headers)
                results["reachable"] = True
                results["status_code"] = response.status_code

                # Check security headers
                security_headers = {
                    "Content-Security-Policy": response.headers.get(
                        "Content-Security-Policy"
                    ),
                    "X-Content-Type-Options": response.headers.get(
                        "X-Content-Type-Options"
                    ),
                    "X-Frame-Options": response.headers.get("X-Frame-Options"),
                    "Strict-Transport-Security": response.headers.get(
                        "Strict-Transport-Security"
                    ),
                }
                results["security_headers"] = {
                    k: v for k, v in security_headers.items() if v
                }

                # Check for missing security headers
                if not security_headers.get("X-Content-Type-Options"):
                    results["issues"].append("Missing X-Content-Type-Options header")
                if not security_headers.get("X-Frame-Options"):
                    results["issues"].append("Missing X-Frame-Options header")
                if endpoint_url.startswith("https://") and not security_headers.get(
                    "Strict-Transport-Security"
                ):
                    results["issues"].append("Missing Strict-Transport-Security header")

            except Exception as e:
                results["issues"].append(f"Failed to reach endpoint: {str(e)}")

            # Try to fetch agent card
            agent_card_urls = [
                urljoin(endpoint_url, "/.well-known/agent-card.json"),
                urljoin(endpoint_url, "/agent-card"),
                urljoin(endpoint_url, "/agent-card.json"),
            ]

            for url in agent_card_urls:
                try:
                    response = await client.get(url, headers=headers)
                    if response.status_code == 200:
                        results["has_agent_card"] = True
                        results["agent_card_url"] = url
                        try:
                            agent_card = response.json()
                            results["agent_name"] = agent_card.get("name")
                        except Exception:
                            pass
                        break
                except Exception:
                    continue

            if not results["has_agent_card"]:
                results["issues"].append("No agent card found at standard locations")

            # Try health endpoint
            health_urls = [
                urljoin(endpoint_url, "/health"),
                urljoin(endpoint_url, "/healthz"),
            ]

            for url in health_urls:
                try:
                    response = await client.get(url, headers=headers)
                    if response.status_code == 200:
                        results["has_health_endpoint"] = True
                        break
                except Exception:
                    continue

    except Exception as e:
        raise NetworkError(
            f"Failed to test endpoint: {str(e)}", {"endpoint_url": endpoint_url}
        )

    logger.info(
        f"Endpoint test completed: {len(results['issues'])} issues found",
        extra={"endpoint": endpoint_url, "issues": results["issues"]},
    )

    return results


async def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    max_size: int = MAX_RESPONSE_SIZE,
) -> str:
    """Fetch content from a URL.

    Args:
        url: URL to fetch
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        max_size: Maximum response size in bytes

    Returns:
        Response content as string

    Raises:
        NetworkError: If request fails
        ValidationError: If response is too large
    """
    # Validate URL
    url = validate_url(url, allow_localhost=True, allow_private_ips=False)

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=verify_ssl) as client:
            response = await client.get(url, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()

            if len(response.content) > max_size:
                raise ValidationError(
                    "Response too large",
                    {"size": len(response.content), "max": max_size},
                )

            return response.text

    except httpx.TimeoutException:
        raise TimeoutError(f"Request timed out after {timeout}s", {"url": url})
    except httpx.HTTPStatusError as e:
        raise NetworkError(
            f"HTTP {e.response.status_code}",
            {"url": url, "status_code": e.response.status_code},
        )
    except Exception as e:
        raise NetworkError(f"Failed to fetch URL: {str(e)}", {"url": url})
