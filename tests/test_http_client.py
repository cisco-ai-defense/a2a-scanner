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

"""Tests for HTTP client utilities."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from a2ascanner.utils.http_client import (
    fetch_agent_card,
    check_endpoint,
    fetch_url
)
from a2ascanner.exceptions import (
    NetworkError,
    TimeoutError,
    ValidationError,
    SSRFError,
    AuthenticationError
)


class TestFetchAgentCard:
    """Tests for fetch_agent_card function."""
    
    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        """Test successful agent card fetch."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = b'{"name": "Test Agent", "url": "https://example.com"}'
        mock_response.json.return_value = {"name": "Test Agent", "url": "https://example.com"}
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            result = await fetch_agent_card("https://example.com/agent-card")
            
            assert result["name"] == "Test Agent"
            assert result["url"] == "https://example.com"
    
    @pytest.mark.asyncio
    async def test_ssrf_protection(self):
        """Test SSRF protection blocks private IPs."""
        with pytest.raises(SSRFError):
            await fetch_agent_card("http://192.168.1.1/agent-card")
    
    @pytest.mark.asyncio
    async def test_localhost_allowed(self):
        """Test localhost can be allowed."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = b'{"name": "Local Agent", "url": "http://localhost"}'
        mock_response.json.return_value = {"name": "Local Agent", "url": "http://localhost"}
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            result = await fetch_agent_card("http://localhost:8000/agent-card", allow_localhost=True)
            
            assert result["name"] == "Local Agent"
    
    @pytest.mark.asyncio
    async def test_timeout(self):
        """Test timeout handling."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.TimeoutException("Timeout")
            )
            
            with pytest.raises(TimeoutError):
                await fetch_agent_card("https://example.com/agent-card", timeout=1.0)
    
    @pytest.mark.asyncio
    async def test_connection_error(self):
        """Test connection error handling."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.ConnectError("Connection failed")
            )
            
            with pytest.raises(NetworkError):
                await fetch_agent_card("https://example.com/agent-card")
    
    @pytest.mark.asyncio
    async def test_404_error(self):
        """Test 404 error handling."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            with pytest.raises(NetworkError) as exc_info:
                await fetch_agent_card("https://example.com/agent-card")
            
            assert "not found" in exc_info.value.message.lower()
    
    @pytest.mark.asyncio
    async def test_401_authentication_error(self):
        """Test 401 authentication error."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            with pytest.raises(AuthenticationError):
                await fetch_agent_card("https://example.com/agent-card")
    
    @pytest.mark.asyncio
    async def test_invalid_json(self):
        """Test invalid JSON response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = b'{"invalid": }'
        mock_response.json.side_effect = ValueError("Invalid JSON")
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            with pytest.raises(ValidationError):
                await fetch_agent_card("https://example.com/agent-card")
    
    @pytest.mark.asyncio
    async def test_response_too_large(self):
        """Test response size limit."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = b"x" * 20_000_000  # 20MB
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            with pytest.raises(ValidationError) as exc_info:
                await fetch_agent_card("https://example.com/agent-card")
            
            assert "too large" in exc_info.value.message.lower()
    
    @pytest.mark.asyncio
    async def test_bearer_token(self):
        """Test bearer token is included in request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = b'{"name": "Test", "url": "https://example.com"}'
        mock_response.json.return_value = {"name": "Test", "url": "https://example.com"}
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.get = mock_get
            
            await fetch_agent_card(
                "https://example.com/agent-card",
                bearer_token="test-token-123"
            )
            
            # Verify Authorization header was included
            call_args = mock_get.call_args
            headers = call_args[1]["headers"]
            assert "Authorization" in headers
            assert headers["Authorization"] == "Bearer test-token-123"


class TestTestEndpoint:
    """Tests for test_endpoint function."""
    
    @pytest.mark.asyncio
    async def test_reachable_endpoint(self):
        """Test reachable endpoint."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY"
        }
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            result = await check_endpoint("https://example.com")
            
            assert result["reachable"] is True
            assert result["status_code"] == 200
            assert "X-Content-Type-Options" in result["security_headers"]
    
    @pytest.mark.asyncio
    async def test_missing_security_headers(self):
        """Test detection of missing security headers."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            result = await check_endpoint("https://example.com")
            
            assert len(result["issues"]) > 0
            assert any("X-Content-Type-Options" in issue for issue in result["issues"])
    
    @pytest.mark.asyncio
    async def test_agent_card_detection(self):
        """Test agent card detection."""
        mock_base_response = MagicMock()
        mock_base_response.status_code = 200
        mock_base_response.headers = {}
        
        mock_card_response = MagicMock()
        mock_card_response.status_code = 200
        mock_card_response.json.return_value = {"name": "Test Agent"}
        
        with patch("httpx.AsyncClient") as mock_client:
            async def mock_get(url, **kwargs):
                if "agent-card" in url:
                    return mock_card_response
                return mock_base_response
            
            mock_client.return_value.__aenter__.return_value.get = mock_get
            
            result = await check_endpoint("https://example.com")
            
            assert result["has_agent_card"] is True
            assert "agent_card_url" in result


class TestFetchURL:
    """Tests for fetch_url function."""
    
    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        """Test successful URL fetch."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"test content"
        mock_response.text = "test content"
        mock_response.raise_for_status = MagicMock()
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            result = await fetch_url("https://example.com/test")
            
            assert result == "test content"
    
    @pytest.mark.asyncio
    async def test_ssrf_protection(self):
        """Test SSRF protection."""
        with pytest.raises(SSRFError):
            await fetch_url("http://169.254.169.254/latest/meta-data")
    
    @pytest.mark.asyncio
    async def test_timeout(self):
        """Test timeout."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.TimeoutException("Timeout")
            )
            
            with pytest.raises(TimeoutError):
                await fetch_url("https://example.com/test")

