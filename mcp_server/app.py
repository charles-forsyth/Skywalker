"""Cloud Run entrypoint: the Skywalker MCP server on port 8080.

- `/mcp`  Streamable HTTP (current MCP transport), stateless.
- `/sse` + `/messages/`  the deprecated SSE transport, kept one release for
  clients configured with the old `/sse` URL.
- OAuth endpoints and `/health`, `/whoami`, `/signout` from auth.py.

Every MCP request passes `auth.BearerAuth` (Google sign-in, users.yaml checked
per request), then `access.GuardedMCP` (role per tool, audit line per call).
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import AsyncIterator

from access import GuardedMCP
from auth import AuthServer, BearerAuth, build_auth_from_env
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware


def build_app(
    mcp: GuardedMCP,
    auth: AuthServer,
    legacy_sse: bool = True,
    quota_project: str | None = None,
) -> Starlette:
    mcp.google_tokens = auth.google_tokens
    mcp.quota_project = quota_project
    # A fresh session manager per app (FastMCP keeps one, and it can only run once).
    mcp._session_manager = None
    routes = [*auth.routes, *mcp.streamable_http_app().routes]
    if legacy_sse:
        routes += mcp.sse_app().routes

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with mcp.session_manager.run():
            yield

    return Starlette(
        routes=routes,
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
                allow_headers=["*"],
                expose_headers=["WWW-Authenticate", "Mcp-Session-Id"],
            ),
            Middleware(BearerAuth, auth=auth),
        ],
        lifespan=lifespan,
    )


if __name__ == "__main__":
    import uvicorn
    from server import TOOLS_VERSION, mcp

    app = build_app(
        mcp,
        build_auth_from_env(tools_version=TOOLS_VERSION),
        quota_project=os.environ.get("SKYWALKER_QUOTA_PROJECT") or None,
    )
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
