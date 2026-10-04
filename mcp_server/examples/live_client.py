#!/usr/bin/env python3
"""Live test client for the Skywalker MCP server (its own sign-in and token file).

    uv run --with "mcp==1.27.2" --with httpx python mcp_server/examples/live_client.py login
    ... whoami
    ... tools
    ... call skywalker_overview '{"project_id": "my-project"}'

Tokens: ~/.config/skywalker/mcp-live-test-token.json (mode 600). BASE defaults to
the Cloud Run URL; set SKYWALKER_MCP_URL to test another server.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import http.server
import json
import os
import secrets
import sys
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Any

import httpx

BASE = os.environ.get(
    "SKYWALKER_MCP_URL", "https://skywalker-mcp-server-492106370716.us-central1.run.app"
).rstrip("/")
TOKEN_FILE = Path.home() / ".config/skywalker/mcp-live-test-token.json"
PORT = 33419
REDIRECT = f"http://127.0.0.1:{PORT}/callback"


def _save(data: dict[str, Any]) -> None:
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(json.dumps(data))
    TOKEN_FILE.chmod(0o600)


def login() -> None:
    reg = httpx.post(
        f"{BASE}/register",
        json={"redirect_uris": [REDIRECT], "client_name": "skywalker live test"},
    ).json()
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = secrets.token_urlsafe(16)
    got: dict[str, str] = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
            got.update(q)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Signed in. You can close this tab.")

        def log_message(self, *a: Any) -> None:
            pass

    srv = http.server.HTTPServer(("127.0.0.1", PORT), H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    url = f"{BASE}/authorize?" + urllib.parse.urlencode(
        {
            "client_id": reg["client_id"],
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
    )
    print("Opening the browser to sign in:\n", url)
    webbrowser.open(url)
    for _ in range(600):
        if got:
            break
        time.sleep(0.5)
    if got.get("state") != state or "code" not in got:
        sys.exit(f"sign-in failed: {got}")
    tok = httpx.post(
        f"{BASE}/token",
        data={
            "grant_type": "authorization_code",
            "code": got["code"],
            "code_verifier": verifier,
            "redirect_uri": REDIRECT,
            "client_id": reg["client_id"],
        },
    ).json()
    if "access_token" not in tok:
        sys.exit(f"token exchange failed: {tok}")
    tok["client_id"] = reg["client_id"]
    tok["obtained"] = time.time()
    _save(tok)
    print("ok, saved", TOKEN_FILE)


def access_token() -> str:
    tok = json.loads(TOKEN_FILE.read_text())
    if time.time() - tok.get("obtained", 0) > tok.get("expires_in", 3600) - 120:
        new = httpx.post(
            f"{BASE}/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tok["refresh_token"],
                "client_id": tok["client_id"],
            },
        ).json()
        if "access_token" not in new:
            sys.exit(f"refresh failed ({new}); run login again")
        new["client_id"] = tok["client_id"]
        new["obtained"] = time.time()
        _save(new)
        tok = new
    return str(tok["access_token"])


async def mcp_call(
    method: str, name: str = "", args: dict[str, Any] | None = None
) -> Any:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    headers = {"Authorization": f"Bearer {access_token()}"}
    async with (
        streamablehttp_client(
            f"{BASE}/mcp", headers=headers, timeout=120, sse_read_timeout=600
        ) as (r, w, _),
        ClientSession(r, w) as s,
    ):
        await s.initialize()
        if method == "tools":
            return [t.name for t in (await s.list_tools()).tools]
        t0 = time.monotonic()
        res = await s.call_tool(name, args or {})
        ms = int((time.monotonic() - t0) * 1000)
        text = res.content[0].text if res.content else ""
        return {
            "ms": ms,
            "is_error": getattr(res, "isError", getattr(res, "is_error", None)),
            "chars": len(text),
            "text": text if os.environ.get("FULL") else text[:3000],
        }


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "whoami"
    if cmd == "login":
        login()
    elif cmd == "whoami":
        print(
            httpx.get(
                f"{BASE}/whoami", headers={"Authorization": f"Bearer {access_token()}"}
            ).json()
        )
    elif cmd == "tools":
        print(json.dumps(asyncio.run(mcp_call("tools")), indent=1))
    elif cmd == "call":
        args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        print(json.dumps(asyncio.run(mcp_call("call", sys.argv[2], args)), indent=1))
    elif cmd == "signout":
        print(
            httpx.post(
                f"{BASE}/signout", headers={"Authorization": f"Bearer {access_token()}"}
            ).json()
        )
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
