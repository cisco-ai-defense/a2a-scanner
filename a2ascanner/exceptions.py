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

"""Custom exceptions for A2A Scanner.

This module defines the exception hierarchy for the A2A Scanner,
providing specific exception types for different error scenarios
to enable better error handling and reporting.
"""


class A2AScannerError(Exception):
    """Base exception for all A2A Scanner errors.

    All custom exceptions in the scanner inherit from this base class,
    allowing callers to catch all scanner-specific errors with a single
    except clause if desired.
    """

    def __init__(self, message: str, details: dict = None):
        """Initialize the exception.

        Args:
            message: Human-readable error message
            details: Optional dictionary with additional error context
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        """Convert exception to dictionary format for API responses.

        Returns:
            Dictionary with error information
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


class ScannerConfigError(A2AScannerError):
    """Configuration-related errors.

    Raised when there are issues with scanner configuration,
    such as missing required settings, invalid values, or
    conflicting options.

    Example:
        raise ScannerConfigError(
            "Missing LLM API key",
            {"provider": "azure", "required_env": "A2A_SCANNER_LLM_API_KEY"}
        )
    """

    pass


class AnalyzerError(A2AScannerError):
    """Analyzer execution errors.

    Raised when an analyzer fails to complete its analysis,
    such as YARA rule compilation errors, pattern matching failures,
    or internal analyzer logic errors.

    Example:
        raise AnalyzerError(
            "YARA rule compilation failed",
            {"rule_file": "agent_impersonation.yar", "line": 42}
        )
    """

    pass


class NetworkError(A2AScannerError):
    """Network and HTTP request errors.

    Raised for network-related failures including connection errors,
    timeouts, DNS failures, and HTTP errors.

    Example:
        raise NetworkError(
            "Failed to fetch agent card from URL",
            {"url": "https://example.com/agent-card", "status_code": 404}
        )
    """

    pass


class ValidationError(A2AScannerError):
    """Input validation errors.

    Raised when input validation fails, such as invalid file formats,
    malformed JSON, schema validation failures, or invalid parameters.

    Example:
        raise ValidationError(
            "Invalid agent card schema",
            {"missing_fields": ["name", "url"], "file": "agent.json"}
        )
    """

    pass


class TimeoutError(A2AScannerError):
    """Operation timeout errors.

    Raised when an operation exceeds its configured timeout limit,
    such as LLM API calls, HTTP requests, or long-running scans.

    Example:
        raise TimeoutError(
            "Endpoint scan exceeded timeout",
            {"endpoint": "https://agent.example.com", "timeout_seconds": 30}
        )
    """

    pass


class SSRFError(NetworkError):
    """Server-Side Request Forgery prevention errors.

    Raised when a URL fetch request is blocked due to SSRF protection,
    such as attempts to access internal IPs, localhost, or cloud metadata.

    Example:
        raise SSRFError(
            "Blocked request to internal IP address",
            {"url": "http://192.168.1.1", "reason": "private_ip"}
        )
    """

    pass


class ScanError(A2AScannerError):
    """General scanning operation errors.

    Raised for errors during the scanning process that don't fit
    into more specific categories.

    Example:
        raise ScanError(
            "Unable to read file for scanning",
            {"file_path": "/path/to/file.py", "reason": "permission_denied"}
        )
    """

    pass


class AnalyzerNotFoundError(A2AScannerError):
    """Analyzer not found or not available.

    Raised when a requested analyzer is not available or not registered
    with the scanner.

    Example:
        raise AnalyzerNotFoundError(
            "Analyzer 'custom' not found",
            {"requested": "custom", "available": ["yara", "heuristic", "llm"]}
        )
    """

    pass


class RateLimitError(NetworkError):
    """Rate limit exceeded errors.

    Raised when API rate limits are exceeded, either for external
    services (like LLM APIs) or internal rate limiting.

    Example:
        raise RateLimitError(
            "LLM API rate limit exceeded",
            {"provider": "azure", "retry_after": 60, "limit": "10/minute"}
        )
    """

    pass


class AuthenticationError(NetworkError):
    """Authentication and authorization errors.

    Raised when authentication fails for API requests or when
    authorization is required but not provided.

    Example:
        raise AuthenticationError(
            "Invalid API key for endpoint",
            {"endpoint": "https://agent.example.com", "auth_type": "bearer"}
        )
    """

    pass
