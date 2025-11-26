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

"""A2A Scanner Configuration Management

Configuration management system for the A2A Scanner. Handles
environment variable loading, LLM provider configuration, scanner settings,
timeout management, and provides type-safe configuration objects with
validation and default values.
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Configuration class for A2A Scanner.

    Loads configuration from environment variables with sensible defaults.
    """

    def __init__(
        self,
        llm_provider: Optional[str] = None,
        llm_api_key: Optional[str] = None,
        llm_model: Optional[str] = None,
        llm_base_url: Optional[str] = None,
        llm_api_version: Optional[str] = None,
        # Meta-analyzer specific LLM settings (falls back to main LLM settings)
        meta_llm_provider: Optional[str] = None,
        meta_llm_api_key: Optional[str] = None,
        meta_llm_model: Optional[str] = None,
        meta_llm_base_url: Optional[str] = None,
        meta_llm_api_version: Optional[str] = None,
        log_level: Optional[str] = None,
        max_concurrent_scans: Optional[int] = None,
        timeout: Optional[int] = None,
        dev_mode: Optional[bool] = None,
    ):
        """Initialize configuration.

        Args:
            llm_provider: LLM provider (openai, anthropic, azure, ollama)
            llm_api_key: API key for LLM provider
            llm_model: Model name to use
            llm_base_url: Base URL for LLM API (Azure/Ollama)
            llm_api_version: API version (Azure)
            meta_llm_provider: LLM provider for meta-analyzer (defaults to llm_provider)
            meta_llm_api_key: API key for meta-analyzer (defaults to llm_api_key)
            meta_llm_model: Model for meta-analyzer (defaults to llm_model)
            meta_llm_base_url: Base URL for meta-analyzer (defaults to llm_base_url)
            meta_llm_api_version: API version for meta-analyzer (defaults to llm_api_version)
            log_level: Logging level
            max_concurrent_scans: Maximum concurrent scans
            timeout: Request timeout in seconds
            dev_mode: Enable development mode (relaxed security checks)
        """
        # LLM Configuration (primary analyzer)
        self.llm_provider = llm_provider or os.getenv(
            "A2A_SCANNER_LLM_PROVIDER", "openai"
        )
        self.llm_api_key = llm_api_key or os.getenv("A2A_SCANNER_LLM_API_KEY")
        self.llm_model = llm_model or os.getenv("A2A_SCANNER_LLM_MODEL", "gpt-4.1")
        self.llm_base_url = llm_base_url or os.getenv("A2A_SCANNER_LLM_BASE_URL")
        self.llm_api_version = llm_api_version or os.getenv(
            "A2A_SCANNER_LLM_API_VERSION"
        )

        # Meta-Analyzer LLM Configuration (falls back to primary LLM settings)
        self.meta_llm_provider = (
            meta_llm_provider
            or os.getenv("A2A_SCANNER_META_LLM_PROVIDER")
            or self.llm_provider
        )
        self.meta_llm_api_key = (
            meta_llm_api_key
            or os.getenv("A2A_SCANNER_META_LLM_API_KEY")
            or self.llm_api_key
        )
        self.meta_llm_model = (
            meta_llm_model
            or os.getenv("A2A_SCANNER_META_LLM_MODEL")
            or self.llm_model
        )
        self.meta_llm_base_url = (
            meta_llm_base_url
            or os.getenv("A2A_SCANNER_META_LLM_BASE_URL")
            or self.llm_base_url
        )
        self.meta_llm_api_version = (
            meta_llm_api_version
            or os.getenv("A2A_SCANNER_META_LLM_API_VERSION")
            or self.llm_api_version
        )

        # Scanner Configuration
        self.log_level = log_level or os.getenv("A2A_SCANNER_LOG_LEVEL", "INFO")
        self.max_concurrent_scans = max_concurrent_scans or int(
            os.getenv("A2A_SCANNER_MAX_CONCURRENT_SCANS", "5")
        )
        self.timeout = timeout or int(os.getenv("A2A_SCANNER_TIMEOUT", "30"))

        # Development Mode
        # When enabled, relaxes security checks for easier local testing:
        # - Allows localhost URLs
        # - Allows private IP addresses
        # - Skips SSL certificate verification
        # - Allows HTTP (insecure) connections
        self.dev_mode = (
            dev_mode
            if dev_mode is not None
            else (
                os.getenv("A2A_SCANNER_DEV_MODE", "false").lower()
                in ("true", "1", "yes")
            )
        )

        # API Server Configuration
        self.api_host = os.getenv("A2A_SCANNER_API_HOST", "0.0.0.0")
        self.api_port = int(os.getenv("A2A_SCANNER_API_PORT", "8000"))

    def validate(self) -> bool:
        """Validate configuration.

        Returns:
            True if configuration is valid
        """
        # LLM API key is optional (YARA and pattern analyzers work without it)
        return True

    def __repr__(self) -> str:
        """String representation of config (without sensitive data)."""
        return (
            f"Config(llm_provider={self.llm_provider}, "
            f"llm_model={self.llm_model}, "
            f"log_level={self.log_level})"
        )
