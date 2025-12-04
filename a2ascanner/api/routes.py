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

"""API routes module for A2A Scanner.

This module defines the HTTP API endpoints for the A2A Scanner, including
routes for scanning agent cards, health checks, and result retrieval.
"""

import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from a2ascanner.core.scanner import Scanner
from a2ascanner.config.config import Config
from a2ascanner.utils.http_client import fetch_agent_card
from a2ascanner.exceptions import (
    NetworkError,
    TimeoutError,
    ValidationError,
    SSRFError,
    AuthenticationError,
    A2AScannerError,
)
from a2ascanner.utils.logging_config import set_correlation_id, get_logger

logger = get_logger(__name__)


router = APIRouter()


# Request models
class AgentCardScanRequest(BaseModel):
    """Request model for agent card scan."""

    agent_card_url: Optional[str] = Field(None, description="URL to agent card")
    agent_card_json: Optional[str] = Field(None, description="Agent card JSON string")
    agent_card_data: Optional[Dict[str, Any]] = Field(
        None, description="Agent card as dict"
    )
    analyzers: List[str] = Field(
        default=["yara", "llm"], description="Analyzers to use"
    )

    # Allow the root to be the agent card itself
    class Config:
        extra = "allow"


class SourceCodeScanRequest(BaseModel):
    """Request model for source code scan."""

    directory: str = Field(..., description="Path to source code directory")
    analyzers: List[str] = Field(
        default=["yara", "static"], description="Analyzers to use"
    )


class EndpointScanRequest(BaseModel):
    """Request model for endpoint scan."""

    endpoint_url: str = Field(..., description="Endpoint URL to scan")


class FullScanRequest(BaseModel):
    """Request model for full scan."""

    directory: str = Field(..., description="Path to source code directory")
    agent_card_url: Optional[str] = Field(None, description="URL to agent card")
    endpoint_url: Optional[str] = Field(None, description="Endpoint URL to test")
    analyzers: List[str] = Field(
        default=["yara", "llm", "static"], description="Analyzers to use"
    )


# Response models
class ScanResponse(BaseModel):
    """Response model for scan operations."""

    success: bool
    message: str
    result: Optional[Dict[str, Any]] = None


# Routes
@router.post("/scan/agent-card", response_model=ScanResponse)
async def scan_agent_card(request: AgentCardScanRequest):
    """Scan an A2A agent card.

    Performs shallow security scan of an agent card using specified analyzers.
    """
    # Set correlation ID for request tracking
    request_id = set_correlation_id()

    try:
        config = Config()
        scanner = Scanner(config)

        # Check if the request itself is the agent card (direct JSON post)
        request_dict = request.model_dump(exclude_unset=True)

        # If none of the special fields are set, treat the whole request as agent card
        if (
            not request.agent_card_url
            and not request.agent_card_json
            and not request.agent_card_data
        ):
            # Remove our custom fields if they exist
            agent_card = {
                k: v for k, v in request_dict.items() if k not in ["analyzers"]
            }
            if agent_card and "name" in agent_card:  # Looks like an agent card
                result = await scanner.scan_agent_card(agent_card)
            else:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": {
                            "code": "INVALID_REQUEST",
                            "message": "Must provide one of: agent_card_url, agent_card_json, agent_card_data, or a valid agent card JSON",
                            "request_id": request_id,
                        }
                    },
                )
        elif request.agent_card_url:
            # Fetch from URL
            try:
                logger.info(f"Fetching agent card from URL: {request.agent_card_url}")
                agent_card = await fetch_agent_card(
                    url=request.agent_card_url,
                    timeout=30.0,
                    verify_ssl=not config.dev_mode,  # Skip SSL verification in dev mode
                    allow_localhost=config.dev_mode,  # Allow localhost in dev mode
                    allow_private_ips=config.dev_mode,  # Allow private IPs in dev mode
                )
                result = await scanner.scan_agent_card(agent_card)
                logger.info("Successfully scanned agent card from URL")
            except SSRFError as e:
                logger.error(f"SSRF protection blocked URL: {e.message}")
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": {
                            "code": "SSRF_BLOCKED",
                            "message": e.message,
                            "details": e.details,
                            "request_id": request_id,
                        }
                    },
                )
            except AuthenticationError as e:
                logger.error(f"Authentication failed: {e.message}")
                raise HTTPException(
                    status_code=401,
                    detail={
                        "error": {
                            "code": "AUTH_FAILED",
                            "message": e.message,
                            "details": e.details,
                            "request_id": request_id,
                        }
                    },
                )
            except TimeoutError as e:
                logger.error(f"Request timed out: {e.message}")
                raise HTTPException(
                    status_code=504,
                    detail={
                        "error": {
                            "code": "TIMEOUT",
                            "message": e.message,
                            "details": e.details,
                            "request_id": request_id,
                        }
                    },
                )
            except NetworkError as e:
                logger.error(f"Network error: {e.message}")
                raise HTTPException(
                    status_code=502,
                    detail={
                        "error": {
                            "code": "NETWORK_ERROR",
                            "message": e.message,
                            "details": e.details,
                            "request_id": request_id,
                        }
                    },
                )
            except ValidationError as e:
                logger.error(f"Validation error: {e.message}")
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": e.message,
                            "details": e.details,
                            "request_id": request_id,
                        }
                    },
                )
        elif request.agent_card_json:
            agent_card = json.loads(request.agent_card_json)
            result = await scanner.scan_agent_card(agent_card)
        else:  # agent_card_data
            result = await scanner.scan_agent_card(request.agent_card_data)

        return ScanResponse(
            success=True, message="Agent card scan completed", result=result.to_dict()
        )

    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "INVALID_JSON",
                    "message": f"Invalid JSON: {str(e)}",
                    "request_id": request_id,
                }
            },
        )
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except A2AScannerError as e:
        logger.error(f"Scanner error: {e.message}", extra={"details": e.details})
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": e.__class__.__name__.upper(),
                    "message": e.message,
                    "details": e.details,
                    "request_id": request_id,
                }
            },
        )
    except Exception as e:
        logger.exception("Unexpected error in scan_agent_card")
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": str(e),
                    "request_id": request_id,
                }
            },
        )


@router.post("/scan/source-code", response_model=ScanResponse)
async def scan_source_code(request: SourceCodeScanRequest):
    """Scan A2A agent source code.

    Performs deep security scan of source code using specified analyzers.
    """
    try:
        config = Config()
        scanner = Scanner(config)

        # Scan directory using scan_file on all files
        directory = Path(request.directory)
        if not directory.exists():
            raise HTTPException(
                status_code=404, detail=f"Directory not found: {request.directory}"
            )

        # For now, scan individual files and aggregate results
        # In a full implementation, you'd want Scanner.scan_directory()
        all_findings = []
        for file_path in directory.rglob("*.py"):
            result = await scanner.scan_file(str(file_path))
            all_findings.extend(result.findings)

        # Create aggregated result
        result_dict = {
            "target_type": "source_code",
            "target_name": str(directory),
            "status": "scanned",
            "analyzers": list(scanner.analyzers.keys()),
            "findings_count": len(all_findings),
            "findings": [f.to_dict() for f in all_findings],
        }

        return ScanResponse(
            success=True, message="Source code scan completed", result=result_dict
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/endpoint", response_model=ScanResponse)
async def scan_endpoint(request: EndpointScanRequest):
    """Scan an A2A agent endpoint.

    Performs dynamic security testing of a running agent endpoint.
    """
    # Set correlation ID for request tracking
    request_id = set_correlation_id()

    try:
        config = Config()
        scanner = Scanner(config)

        logger.info(f"Starting endpoint scan: {request.endpoint_url}")

        # Scan the endpoint
        result = await scanner.scan_endpoint(
            endpoint_url=request.endpoint_url,
            timeout=30.0,
            verify_ssl=not config.dev_mode,  # Skip SSL verification in dev mode
        )

        logger.info(f"Endpoint scan completed: {request.endpoint_url}")

        return ScanResponse(
            success=True, message="Endpoint scan completed", result=result.to_dict()
        )

    except SSRFError as e:
        logger.error(f"SSRF protection blocked endpoint: {e.message}")
        raise HTTPException(
            status_code=403,
            detail={
                "error": {
                    "code": "SSRF_BLOCKED",
                    "message": e.message,
                    "details": e.details,
                    "request_id": request_id,
                }
            },
        )
    except TimeoutError as e:
        logger.error(f"Endpoint scan timed out: {e.message}")
        raise HTTPException(
            status_code=504,
            detail={
                "error": {
                    "code": "TIMEOUT",
                    "message": e.message,
                    "details": e.details,
                    "request_id": request_id,
                }
            },
        )
    except NetworkError as e:
        logger.error(f"Network error during endpoint scan: {e.message}")
        raise HTTPException(
            status_code=502,
            detail={
                "error": {
                    "code": "NETWORK_ERROR",
                    "message": e.message,
                    "details": e.details,
                    "request_id": request_id,
                }
            },
        )
    except ValidationError as e:
        logger.error(f"Validation error: {e.message}")
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": e.message,
                    "details": e.details,
                    "request_id": request_id,
                }
            },
        )
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except A2AScannerError as e:
        logger.error(f"Scanner error: {e.message}", extra={"details": e.details})
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": e.__class__.__name__.upper(),
                    "message": e.message,
                    "details": e.details,
                    "request_id": request_id,
                }
            },
        )
    except Exception as e:
        logger.exception("Unexpected error in scan_endpoint")
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": str(e),
                    "request_id": request_id,
                }
            },
        )


@router.post("/scan/full", response_model=ScanResponse)
async def full_scan(request: FullScanRequest):
    """Perform comprehensive scan of an A2A agent.

    Scans agent card (if provided), source code, and endpoint (if provided).
    """
    try:
        config = Config()
        scanner = Scanner(config)
        results = {}

        # Scan agent card if provided
        if request.agent_card_url:
            # URL fetching not implemented
            results["agent_card"] = {"error": "URL fetching not yet implemented"}

        # Scan source code
        directory = Path(request.directory)
        if directory.exists():
            all_findings = []
            for file_path in directory.rglob("*.py"):
                result = await scanner.scan_file(str(file_path))
                all_findings.extend(result.findings)

            results["source_code"] = {
                "target_type": "source_code",
                "target_name": str(directory),
                "status": "scanned",
                "findings_count": len(all_findings),
                "findings": [f.to_dict() for f in all_findings],
            }
        else:
            results["source_code"] = {
                "error": f"Directory not found: {request.directory}"
            }

        # Endpoint scanning not implemented
        if request.endpoint_url:
            results["endpoint"] = {"error": "Endpoint scanning not yet implemented"}

        return ScanResponse(success=True, message="Full scan completed", result=results)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "a2a-scanner"}


@router.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "service": "A2A Scanner API",
        "version": "1.0.0",
        "description": "Security scanner for A2A protocol implementations",
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "scan_agent_card": "/scan/agent-card",
            "scan_source_code": "/scan/source-code",
            "scan_endpoint": "/scan/endpoint",
            "full_scan": "/scan/full",
        },
    }
