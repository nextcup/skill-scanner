# Copyright 2026 Cisco Systems, Inc.
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

"""API module for Skill Scanner.

This module provides a FastAPI application for scanning agent skills packages.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.staticfiles import StaticFiles

from .. import __version__ as PACKAGE_VERSION
from .router import router as api_router

app = FastAPI(
    title="Skill Scanner API",
    description="Security scanning API for agent skills packages",
    version=PACKAGE_VERSION,
    docs_url=None,
    redoc_url=None,
)

app.include_router(api_router)


@app.get("/docs", include_in_schema=False)
async def swagger_ui_html():
    """Serve Swagger UI with local static assets for offline support."""
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="Skill Scanner API",
        swagger_js_url="/static/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui.css",
    )


@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    """Serve ReDoc with local static assets for offline support."""
    return get_redoc_html(
        openapi_url="/openapi.json",
        title="Skill Scanner API - ReDoc",
        redoc_js_url="/static/redoc.standalone.js",
    )


# Mount static files directory for Swagger UI assets
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
