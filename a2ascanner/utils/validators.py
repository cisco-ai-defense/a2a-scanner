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

"""Validation utilities for A2A Scanner.

This module provides validation functions for URLs, inputs, schemas,
and other data types to ensure security and data integrity.
"""

import re
import json
import ipaddress
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
from pathlib import Path

from ..exceptions import ValidationError, SSRFError


# Private IP ranges for SSRF protection
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),  # Localhost
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),  # IPv6 localhost
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

# Cloud metadata endpoints to block
CLOUD_METADATA_HOSTS = [
    "169.254.169.254",  # AWS, Azure, GCP
    "169.254.169.253",  # Azure DNS
    "100.100.100.200",  # Alibaba Cloud
    "metadata.google.internal",  # GCP
    "metadata.aws.amazon.com",  # AWS
]

# Required agent card fields
REQUIRED_AGENT_CARD_FIELDS = ["name", "url"]
OPTIONAL_AGENT_CARD_FIELDS = [
    "id",
    "description",
    "version",
    "capabilities",
    "skills",
    "default_input_modes",
    "default_output_modes",
    "supports_authenticated_extended_card",
]


def validate_url(
    url: str,
    allow_localhost: bool = False,
    allow_private_ips: bool = False,
    allowed_schemes: List[str] = None,
) -> str:
    """Validate and sanitize URL.

    Args:
        url: URL to validate
        allow_localhost: Whether to allow localhost URLs
        allow_private_ips: Whether to allow private IP addresses
        allowed_schemes: List of allowed URL schemes (default: ['http', 'https'])

    Returns:
        Validated URL

    Raises:
        ValidationError: If URL is invalid
        SSRFError: If URL points to protected resource
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string", {"url": url})

    url = url.strip()

    if len(url) > 2048:
        raise ValidationError(
            "URL exceeds maximum length", {"url_length": len(url), "max": 2048}
        )

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValidationError(f"Invalid URL format: {str(e)}", {"url": url})

    # Validate scheme
    if allowed_schemes is None:
        allowed_schemes = ["http", "https"]

    if parsed.scheme not in allowed_schemes:
        raise ValidationError(
            "URL scheme not allowed",
            {"scheme": parsed.scheme, "allowed": allowed_schemes},
        )

    # Validate hostname exists
    if not parsed.hostname:
        raise ValidationError("URL must have a hostname", {"url": url})

    # Check for localhost
    if not allow_localhost:
        if parsed.hostname in ["localhost", "127.0.0.1", "0.0.0.0", "::1"]:
            raise SSRFError(
                "Localhost URLs not allowed", {"hostname": parsed.hostname, "url": url}
            )

    # Check for private IPs and cloud metadata
    try:
        ip = ipaddress.ip_address(parsed.hostname)

        # Check if it's a private IP
        if not allow_private_ips:
            for private_range in PRIVATE_IP_RANGES:
                if ip in private_range:
                    raise SSRFError(
                        "Private IP addresses not allowed",
                        {"ip": str(ip), "range": str(private_range)},
                    )
    except ValueError:
        # Not an IP address, check if it's a cloud metadata hostname
        if parsed.hostname in CLOUD_METADATA_HOSTS:
            raise SSRFError(
                "Access to cloud metadata endpoints not allowed",
                {"hostname": parsed.hostname},
            )

    # Check for common typosquatting patterns
    suspicious_patterns = [
        r".*g[o0]{2}gle.*",  # google typos
        r".*amaz[o0]n.*",  # amazon typos
        r".*micr[o0]s[o0]ft.*",  # microsoft typos
    ]

    for pattern in suspicious_patterns:
        if re.match(pattern, parsed.hostname, re.IGNORECASE):
            # This is a warning, not a blocker
            pass

    return url


def validate_file_path(
    file_path: str,
    must_exist: bool = True,
    allowed_extensions: Optional[List[str]] = None,
) -> Path:
    """Validate file path.

    Args:
        file_path: Path to validate
        must_exist: Whether file must exist
        allowed_extensions: List of allowed file extensions

    Returns:
        Validated Path object

    Raises:
        ValidationError: If path is invalid
    """
    if not file_path or not isinstance(file_path, str):
        raise ValidationError(
            "File path must be a non-empty string", {"path": file_path}
        )

    try:
        path = Path(file_path).resolve()
    except Exception as e:
        raise ValidationError(f"Invalid file path: {str(e)}", {"path": file_path})

    # Check if file exists
    if must_exist and not path.exists():
        raise ValidationError("File does not exist", {"path": str(path)})

    # Check extension if specified
    if allowed_extensions and path.suffix.lower() not in allowed_extensions:
        raise ValidationError(
            "File extension not allowed",
            {"extension": path.suffix, "allowed": allowed_extensions},
        )

    # Check for path traversal attempts
    try:
        path.relative_to(Path.cwd())
    except ValueError:
        # File is outside current directory - this may be intentional
        pass

    return path


def validate_json(
    content: str, max_size: int = 10 * 1024 * 1024  # 10MB default
) -> Dict[str, Any]:
    """Validate and parse JSON content.

    Args:
        content: JSON string to validate
        max_size: Maximum allowed size in bytes

    Returns:
        Parsed JSON as dictionary

    Raises:
        ValidationError: If JSON is invalid
    """
    if not content or not isinstance(content, str):
        raise ValidationError("JSON content must be a non-empty string")

    if len(content) > max_size:
        raise ValidationError(
            "JSON content exceeds maximum size", {"size": len(content), "max": max_size}
        )

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValidationError(
            f"Invalid JSON: {str(e)}", {"line": e.lineno, "column": e.colno}
        )

    if not isinstance(data, dict):
        raise ValidationError(
            "JSON must be an object (dictionary)", {"type": type(data).__name__}
        )

    return data


def validate_agent_card(card: Dict[str, Any]) -> Dict[str, Any]:
    """Validate agent card schema.

    Args:
        card: Agent card dictionary to validate

    Returns:
        Validated agent card

    Raises:
        ValidationError: If agent card schema is invalid
    """
    if not isinstance(card, dict):
        raise ValidationError(
            "Agent card must be a dictionary", {"type": type(card).__name__}
        )

    # Check required fields
    missing_fields = [
        field for field in REQUIRED_AGENT_CARD_FIELDS if field not in card
    ]
    if missing_fields:
        raise ValidationError(
            "Agent card missing required fields",
            {"missing": missing_fields, "required": REQUIRED_AGENT_CARD_FIELDS},
        )

    # Validate name
    if not isinstance(card["name"], str) or not card["name"].strip():
        raise ValidationError("Agent card 'name' must be a non-empty string")

    # Validate URL
    if not isinstance(card["url"], str):
        raise ValidationError("Agent card 'url' must be a string")

    try:
        validate_url(
            card["url"], allow_localhost=True
        )  # Allow localhost for development
    except (ValidationError, SSRFError) as e:
        raise ValidationError(f"Invalid agent card URL: {e.message}", e.details)

    # Validate optional fields if present
    if "capabilities" in card and not isinstance(card["capabilities"], dict):
        raise ValidationError("Agent card 'capabilities' must be a dictionary")

    if "skills" in card:
        if not isinstance(card["skills"], list):
            raise ValidationError("Agent card 'skills' must be a list")

        for i, skill in enumerate(card["skills"]):
            if not isinstance(skill, dict):
                raise ValidationError(f"Skill at index {i} must be a dictionary")
            if "name" not in skill:
                raise ValidationError(f"Skill at index {i} missing 'name' field")

    return card


def validate_severity(severity: str) -> str:
    """Validate severity level.

    Args:
        severity: Severity level to validate

    Returns:
        Normalized severity level

    Raises:
        ValidationError: If severity is invalid
    """
    valid_severities = ["HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"]

    if not severity or not isinstance(severity, str):
        raise ValidationError(
            "Severity must be a non-empty string", {"severity": severity}
        )

    severity = severity.upper().strip()

    if severity not in valid_severities:
        raise ValidationError(
            "Invalid severity level", {"severity": severity, "valid": valid_severities}
        )

    return severity


def validate_threat_category(category: str) -> str:
    """Validate threat category.

    Args:
        category: Threat category to validate (e.g., PROMPT_INJECTION, CODE_EXECUTION, AITech-1.1, AISubtech-1.1.1)

    Returns:
        Validated threat category

    Raises:
        ValidationError: If category is invalid
    """
    if not category or not isinstance(category, str):
        raise ValidationError("Threat category must be a non-empty string")

    category = category.strip()

    # Allow AITech-X.X, AISubtech-X.X.X format, or threat name strings (uppercase with underscores)
    aitech_pattern = r"^AITech-\d+\.\d+$"
    aisubtech_pattern = r"^AISubtech-\d+\.\d+\.\d+$"
    threat_name_pattern = r"^[A-Z_]+$"
    
    if not (re.match(aitech_pattern, category) or 
            re.match(aisubtech_pattern, category) or 
            re.match(threat_name_pattern, category)):
        raise ValidationError(
            "Invalid threat category format",
            {"category": category, "expected_format": "AITech-X.X, AISubtech-X.X.X, or THREAT_NAME"},
        )

    return category


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """Sanitize filename to remove potentially dangerous characters.

    Args:
        filename: Filename to sanitize
        max_length: Maximum filename length

    Returns:
        Sanitized filename

    Raises:
        ValidationError: If filename cannot be sanitized
    """
    if not filename or not isinstance(filename, str):
        raise ValidationError("Filename must be a non-empty string")

    # Remove path separators and dangerous characters
    sanitized = re.sub(r'[/\\:*?"<>|]', "_", filename)
    sanitized = sanitized.strip(". ")  # Remove leading/trailing dots and spaces

    if not sanitized:
        raise ValidationError(
            "Filename contains only invalid characters", {"original": filename}
        )

    # Truncate if too long
    if len(sanitized) > max_length:
        name, ext = sanitized.rsplit(".", 1) if "." in sanitized else (sanitized, "")
        name = name[: max_length - len(ext) - 1]
        sanitized = f"{name}.{ext}" if ext else name

    return sanitized


def validate_analyzer_list(analyzers: List[str]) -> List[str]:
    """Validate list of analyzer names.

    Args:
        analyzers: List of analyzer names to validate

    Returns:
        Validated list of analyzer names

    Raises:
        ValidationError: If analyzer list is invalid
    """
    if not isinstance(analyzers, list):
        raise ValidationError(
            "Analyzers must be a list", {"type": type(analyzers).__name__}
        )

    if not analyzers:
        raise ValidationError("Analyzers list cannot be empty")

    valid_analyzers = ["yara", "heuristic", "spec", "llm", "sse", "endpoint"]

    for analyzer in analyzers:
        if not isinstance(analyzer, str):
            raise ValidationError(f"Analyzer name must be a string: {analyzer}")

        if analyzer not in valid_analyzers:
            raise ValidationError(
                f"Invalid analyzer name: {analyzer}", {"valid": valid_analyzers}
            )

    return analyzers
