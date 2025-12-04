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

"""Tests for custom exceptions."""

import pytest
from a2ascanner.exceptions import (
    A2AScannerError,
    NetworkError,
    ValidationError,
    TimeoutError,
    SSRFError,
    ScannerConfigError,
    AnalyzerError,
    RateLimitError,
    AuthenticationError
)


def test_base_exception():
    """Test base A2AScannerError."""
    error = A2AScannerError("Test error", {"key": "value"})
    assert error.message == "Test error"
    assert error.details == {"key": "value"}
    assert str(error) == "Test error"
    
    error_dict = error.to_dict()
    assert error_dict["error_type"] == "A2AScannerError"
    assert error_dict["message"] == "Test error"
    assert error_dict["details"] == {"key": "value"}


def test_network_error():
    """Test NetworkError."""
    error = NetworkError("Connection failed", {"url": "https://example.com"})
    assert error.message == "Connection failed"
    assert error.details["url"] == "https://example.com"
    assert isinstance(error, A2AScannerError)


def test_validation_error():
    """Test ValidationError."""
    error = ValidationError("Invalid input", {"field": "name"})
    assert error.message == "Invalid input"
    assert error.details["field"] == "name"


def test_timeout_error():
    """Test TimeoutError."""
    error = TimeoutError("Request timed out", {"timeout_seconds": 30})
    assert error.message == "Request timed out"
    assert error.details["timeout_seconds"] == 30


def test_ssrf_error():
    """Test SSRFError inheritance."""
    error = SSRFError("Blocked private IP", {"ip": "192.168.1.1"})
    assert error.message == "Blocked private IP"
    assert isinstance(error, NetworkError)
    assert isinstance(error, A2AScannerError)


def test_scanner_config_error():
    """Test ScannerConfigError."""
    error = ScannerConfigError("Missing API key", {"provider": "azure"})
    assert error.message == "Missing API key"
    assert error.details["provider"] == "azure"


def test_analyzer_error():
    """Test AnalyzerError."""
    error = AnalyzerError("YARA compilation failed", {"rule": "test.yar"})
    assert error.message == "YARA compilation failed"
    assert error.details["rule"] == "test.yar"


def test_rate_limit_error():
    """Test RateLimitError."""
    error = RateLimitError("Rate limit exceeded", {"retry_after": 60})
    assert error.message == "Rate limit exceeded"
    assert error.details["retry_after"] == 60
    assert isinstance(error, NetworkError)


def test_authentication_error():
    """Test AuthenticationError."""
    error = AuthenticationError("Invalid API key", {"endpoint": "https://api.example.com"})
    assert error.message == "Invalid API key"
    assert error.details["endpoint"] == "https://api.example.com"
    assert isinstance(error, NetworkError)


def test_exception_to_dict_format():
    """Test to_dict format is consistent."""
    error = ValidationError("Test", {"field": "test"})
    error_dict = error.to_dict()
    
    # Check required keys
    assert "error_type" in error_dict
    assert "message" in error_dict
    assert "details" in error_dict
    
    # Check types
    assert isinstance(error_dict["error_type"], str)
    assert isinstance(error_dict["message"], str)
    assert isinstance(error_dict["details"], dict)

