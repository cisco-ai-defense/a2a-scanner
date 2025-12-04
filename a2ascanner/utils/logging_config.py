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

"""Logging configuration module for A2A Scanner.

This module provides centralized logging configuration for the A2A Scanner,
including consistent logging setup, log level management, formatter configuration,
and output handlers for console and file-based logging across all modules.
"""

import logging
import json
import sys
import uuid
from typing import Optional, Dict, Any
from datetime import datetime
from contextvars import ContextVar

# Context variables for request tracking
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
scan_context: ContextVar[Dict[str, Any]] = ContextVar("scan_context", default={})


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging.

    Outputs log messages in JSON format with consistent structure
    including timestamp, level, message, and contextual information.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.

        Args:
            record: Log record to format

        Returns:
            JSON-formatted log string
        """
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add correlation ID if available
        cid = correlation_id.get()
        if cid:
            log_data["correlation_id"] = cid

        # Add scan context if available
        context = scan_context.get()
        if context:
            log_data["context"] = context

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        return json.dumps(log_data)


class ContextAdapter(logging.LoggerAdapter):
    """Logger adapter that adds contextual information to logs.

    Automatically includes correlation ID, scan context, and custom
    extra fields in all log messages.
    """

    def process(self, msg, kwargs):
        """Add context to log message.

        Args:
            msg: Log message
            kwargs: Keyword arguments

        Returns:
            Tuple of (message, kwargs) with added context
        """
        # Get correlation ID
        cid = correlation_id.get()
        if cid and "extra" not in kwargs:
            kwargs["extra"] = {}
        if cid:
            kwargs["extra"]["correlation_id"] = cid

        # Get scan context
        context = scan_context.get()
        if context and "extra" in kwargs:
            kwargs["extra"]["scan_context"] = context

        return msg, kwargs


def setup_logging(
    level: str = "INFO", structured: bool = False, log_file: Optional[str] = None
) -> None:
    """Setup logging configuration.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        structured: Use structured JSON logging instead of text
        log_file: Optional file path for log output
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Create formatter
    if structured:
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # Setup handlers
    handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        handlers=handlers,
        force=True,  # Override any existing configuration
    )

    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(
    name: str,
    level: Optional[str] = None,
    extra_fields: Optional[Dict[str, Any]] = None,
) -> logging.Logger:
    """Get a logger instance with optional context.

    Args:
        name: Logger name (typically __name__)
        level: Optional logging level override
        extra_fields: Optional extra fields to include in all logs

    Returns:
        Logger instance or ContextAdapter for contextual logging
    """
    logger = logging.getLogger(name)

    if level:
        numeric_level = getattr(logging, level.upper(), logging.INFO)
        logger.setLevel(numeric_level)

    # Wrap in adapter if extra fields provided
    if extra_fields:
        return ContextAdapter(logger, extra_fields)

    return logger


def set_correlation_id(request_id: Optional[str] = None) -> str:
    """Set correlation ID for request tracking.

    Args:
        request_id: Optional custom request ID, generates one if not provided

    Returns:
        The correlation ID that was set
    """
    cid = request_id or str(uuid.uuid4())
    correlation_id.set(cid)
    return cid


def get_correlation_id() -> str:
    """Get current correlation ID.

    Returns:
        Current correlation ID or empty string if not set
    """
    return correlation_id.get()


def set_scan_context(context: Dict[str, Any]) -> None:
    """Set scan context for logging.

    Args:
        context: Dictionary with scan metadata (file_path, scan_type, etc.)
    """
    scan_context.set(context)


def clear_scan_context() -> None:
    """Clear scan context."""
    scan_context.set({})


def log_performance(
    logger: logging.Logger, operation: str, duration_ms: float, **kwargs
) -> None:
    """Log performance metrics.

    Args:
        logger: Logger instance
        operation: Operation name
        duration_ms: Duration in milliseconds
        **kwargs: Additional metrics to log
    """
    metrics = {"operation": operation, "duration_ms": round(duration_ms, 2), **kwargs}

    logger.info(
        f"Performance: {operation} completed in {duration_ms:.2f}ms",
        extra={"extra_fields": {"metrics": metrics}},
    )
