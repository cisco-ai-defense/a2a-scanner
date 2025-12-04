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

"""API server module for A2A Scanner.

This module contains the FastAPI server implementation for the A2A Scanner
REST API, providing HTTP endpoints for scanning agent cards and managing
security analysis through a web service interface.
"""

import click
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from a2ascanner.api.routes import router


# Create app instance at module level for uvicorn
app = FastAPI(
    title="A2A Scanner API",
    description="Security scanner for A2A (Agent-to-Agent) protocol implementations",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(router)


@click.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def main(host, port, reload):
    """Start the A2A Scanner API server."""
    click.echo(f"Starting A2A Scanner API server on {host}:{port}")
    click.echo(f"Interactive documentation: http://{host}:{port}/docs")

    uvicorn.run("a2ascanner.api.server:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    main()
