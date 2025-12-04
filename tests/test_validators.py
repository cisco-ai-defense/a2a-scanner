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

"""Tests for validation utilities."""

import pytest
from pathlib import Path
from a2ascanner.utils.validators import (
    validate_url,
    validate_file_path,
    validate_json,
    validate_agent_card,
    validate_severity,
    validate_threat_category,
    sanitize_filename,
    validate_analyzer_list
)
from a2ascanner.exceptions import ValidationError, SSRFError


class TestURLValidation:
    """Tests for URL validation."""
    
    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        url = validate_url("https://example.com/agent")
        assert url == "https://example.com/agent"
    
    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        url = validate_url("http://example.com/agent")
        assert url == "http://example.com/agent"
    
    def test_localhost_blocked_by_default(self):
        """Test localhost is blocked by default."""
        with pytest.raises(SSRFError):
            validate_url("http://localhost:8000")
    
    def test_localhost_allowed(self):
        """Test localhost can be allowed."""
        url = validate_url("http://localhost:8000", allow_localhost=True)
        assert url == "http://localhost:8000"
    
    def test_private_ip_blocked(self):
        """Test private IPs are blocked."""
        with pytest.raises(SSRFError):
            validate_url("http://192.168.1.1")
    
    def test_private_ip_allowed(self):
        """Test private IPs can be allowed."""
        url = validate_url("http://192.168.1.1", allow_private_ips=True)
        assert url == "http://192.168.1.1"
    
    def test_cloud_metadata_blocked(self):
        """Test cloud metadata endpoints are blocked."""
        with pytest.raises(SSRFError):
            validate_url("http://169.254.169.254/latest/meta-data")
    
    def test_invalid_scheme(self):
        """Test invalid URL scheme."""
        with pytest.raises(ValidationError):
            validate_url("ftp://example.com")
    
    def test_url_too_long(self):
        """Test URL exceeding maximum length."""
        long_url = "https://example.com/" + ("a" * 3000)
        with pytest.raises(ValidationError):
            validate_url(long_url)
    
    def test_empty_url(self):
        """Test empty URL."""
        with pytest.raises(ValidationError):
            validate_url("")
    
    def test_url_with_port(self):
        """Test URL with port."""
        url = validate_url("https://example.com:8443/agent", allow_localhost=True)
        assert url == "https://example.com:8443/agent"


class TestJSONValidation:
    """Tests for JSON validation."""
    
    def test_valid_json(self):
        """Test valid JSON."""
        json_str = '{"name": "Test", "value": 123}'
        data = validate_json(json_str)
        assert data == {"name": "Test", "value": 123}
    
    def test_invalid_json(self):
        """Test invalid JSON."""
        with pytest.raises(ValidationError):
            validate_json('{"invalid": }')
    
    def test_json_too_large(self):
        """Test JSON exceeding size limit."""
        large_json = '{"data": "' + ("x" * 20_000_000) + '"}'
        with pytest.raises(ValidationError):
            validate_json(large_json)
    
    def test_json_not_object(self):
        """Test JSON that is not an object."""
        with pytest.raises(ValidationError):
            validate_json('["array"]')
    
    def test_empty_json(self):
        """Test empty JSON string."""
        with pytest.raises(ValidationError):
            validate_json("")


class TestAgentCardValidation:
    """Tests for agent card validation."""
    
    def test_valid_agent_card(self):
        """Test valid agent card."""
        card = {
            "name": "Test Agent",
            "url": "https://example.com"
        }
        result = validate_agent_card(card)
        assert result == card
    
    def test_missing_required_fields(self):
        """Test agent card missing required fields."""
        with pytest.raises(ValidationError) as exc_info:
            validate_agent_card({"name": "Test"})
        assert "missing required fields" in exc_info.value.message.lower()
    
    def test_invalid_name(self):
        """Test agent card with invalid name."""
        with pytest.raises(ValidationError):
            validate_agent_card({"name": "", "url": "https://example.com"})
    
    def test_invalid_url(self):
        """Test agent card with invalid URL."""
        with pytest.raises(ValidationError):
            validate_agent_card({"name": "Test", "url": "not-a-url"})
    
    def test_valid_card_with_capabilities(self):
        """Test agent card with capabilities."""
        card = {
            "name": "Test Agent",
            "url": "https://example.com",
            "capabilities": {"streaming": True}
        }
        result = validate_agent_card(card)
        assert result == card
    
    def test_invalid_capabilities(self):
        """Test agent card with invalid capabilities."""
        with pytest.raises(ValidationError):
            validate_agent_card({
                "name": "Test",
                "url": "https://example.com",
                "capabilities": "not-a-dict"
            })
    
    def test_valid_card_with_skills(self):
        """Test agent card with skills."""
        card = {
            "name": "Test Agent",
            "url": "https://example.com",
            "skills": [{"name": "skill1"}]
        }
        result = validate_agent_card(card)
        assert result == card
    
    def test_invalid_skills(self):
        """Test agent card with invalid skills."""
        with pytest.raises(ValidationError):
            validate_agent_card({
                "name": "Test",
                "url": "https://example.com",
                "skills": [{"missing_name": True}]
            })


class TestSeverityValidation:
    """Tests for severity validation."""
    
    def test_valid_severities(self):
        """Test all valid severity levels."""
        for severity in ["HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"]:
            result = validate_severity(severity)
            assert result == severity
    
    def test_case_insensitive(self):
        """Test severity is case insensitive."""
        result = validate_severity("high")
        assert result == "HIGH"
    
    def test_invalid_severity(self):
        """Test invalid severity."""
        with pytest.raises(ValidationError):
            validate_severity("CRITICAL")
    
    def test_empty_severity(self):
        """Test empty severity."""
        with pytest.raises(ValidationError):
            validate_severity("")


class TestThreatCategoryValidation:
    """Tests for threat category validation."""
    
    def test_valid_category(self):
        """Test valid threat category."""
        result = validate_threat_category("PROMPT_INJECTION")
        assert result == "PROMPT_INJECTION"
    
    def test_valid_category_with_letter(self):
        """Test valid threat category with letter suffix."""
        result = validate_threat_category("CODE_EXECUTION")
        assert result == "CODE_EXECUTION"
    
    def test_invalid_format(self):
        """Test invalid category format."""
        with pytest.raises(ValidationError):
            validate_threat_category("T01")  # Too short
    
    def test_invalid_prefix(self):
        """Test invalid category prefix."""
        with pytest.raises(ValidationError):
            validate_threat_category("A001")
    
    def test_empty_category(self):
        """Test empty category."""
        with pytest.raises(ValidationError):
            validate_threat_category("")


class TestFilenameValidization:
    """Tests for filename sanitization."""
    
    def test_safe_filename(self):
        """Test safe filename."""
        result = sanitize_filename("test.json")
        assert result == "test.json"
    
    def test_filename_with_path_separators(self):
        """Test filename with path separators."""
        result = sanitize_filename("../../../etc/passwd")
        assert "/" not in result
        assert "\\" not in result
    
    def test_filename_with_dangerous_chars(self):
        """Test filename with dangerous characters."""
        result = sanitize_filename('file<>:"|?*.txt')
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result
    
    def test_filename_too_long(self):
        """Test filename exceeding maximum length."""
        long_name = "x" * 300 + ".txt"
        result = sanitize_filename(long_name)
        assert len(result) <= 255


class TestAnalyzerListValidation:
    """Tests for analyzer list validation."""
    
    def test_valid_analyzers(self):
        """Test valid analyzer list."""
        analyzers = ["yara", "heuristic", "llm"]
        result = validate_analyzer_list(analyzers)
        assert result == analyzers
    
    def test_invalid_analyzer(self):
        """Test invalid analyzer name."""
        with pytest.raises(ValidationError):
            validate_analyzer_list(["yara", "invalid"])
    
    def test_empty_list(self):
        """Test empty analyzer list."""
        with pytest.raises(ValidationError):
            validate_analyzer_list([])
    
    def test_not_list(self):
        """Test non-list input."""
        with pytest.raises(ValidationError):
            validate_analyzer_list("yara")

