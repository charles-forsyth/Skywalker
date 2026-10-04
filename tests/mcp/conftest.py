"""Shared fixtures for the Skywalker MCP server tests (mcp_server/).

The OAuth flow runs end to end against a fake Google; MCP calls go over the real
Streamable HTTP transport through Starlette's TestClient. Google Cloud is a fake
HTTP session keyed by URL, which also records which access token made each call.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import threading
import urllib.parse
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
MCP_DIR = ROOT / "mcp_server"
sys.path.insert(0, str(MCP_DIR))
sys.path.insert(0, str(ROOT / "src"))

import auth  # noqa: E402
from store import SealedStore, load_key, new_key  # noqa: E402
from users import Users  # noqa: E402

BASE = "https://testserver"
REDIRECT = "http://127.0.0.1:33418/callback"
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}

USERS_YAML = """
domain: ucr.edu
users:
  - {email: forsythc@ucr.edu, netid: forsythc, role: admin, projects: [home-proj]}
  - {email: mikek@ucr.edu, netid: mikek, role: read, aliases: [michael.kennedy@ucr.edu],
     projects: [lab-one-proj, "lab-two-*"]}
  - {email: staffer@ucr.edu, netid: staffer, role: staff}
  - {email: nolab@ucr.edu, netid: nolab, role: read}
  - {email: gone@ucr.edu, netid: gone, role: admin, disabled: true}
clients:
  - id: skywalker-ultra
    name: Ultra
    max_role: read
    calls_per_min: 5
    redirect_uris: ["http://127.0.0.1/callback"]
  - id: skywalker-gemini-enterprise
    name: Gemini Enterprise
    max_role: admin
    client_secret_sha256: "{ge_sha}"
    redirect_uris:
      - https://vertexaisearch.cloud.google.com/oauth-redirect
      - https://vertexaisearch.cloud.google.com/static/oauth/oauth.html
""".replace("{ge_sha}", hashlib.sha256(b"ge-secret").hexdigest())


class FakeGoogle(auth.Google):
    """Behaves like Google: a refresh token only on first grant or on consent."""

    def __init__(self) -> None:
        super().__init__("google-client-id", "google-secret")
        self.claims: dict[str, Any] = {}
        self.granted: set[str] = set()  # emails that already consented once
        self.scope = f"openid email {auth.GCP_SCOPE}"
        self.consent_next = False
        self.refreshes: list[str] = []
        self.revoked: list[str] = []
        self.dead: set[str] = set()  # refresh tokens Google now rejects
        self._n = 0
        self._lock = threading.Lock()

    async def exchange(self, code: str, redirect_uri: str) -> dict[str, Any]:
        if code != "google-code":
            raise auth.GoogleError("bad code")
        email = self.claims.get("email", "")
        first = email not in self.granted
        self.granted.add(email)
        tokens: dict[str, Any] = {
            "access_token": f"ga-{email}-0",
            "expires_in": 3600,
            "scope": self.scope,
        }
        if first or self.consent_next:
            tokens["refresh_token"] = f"gr-{email}"
        self.consent_next = False
        return {**self.claims, "_tokens": tokens}

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        with self._lock:
            self.refreshes.append(refresh_token)
            self._n += 1
            n = self._n
        if refresh_token in self.dead:
            raise auth.GoogleError("reauth")
        email = refresh_token.removeprefix("gr-")
        return {"access_token": f"ga-{email}-{n}", "expires_in": 3600}

    def revoke(self, token: str) -> None:
        self.revoked.append(token)


class FakeResponse:
    def __init__(self, status: int, data: Any) -> None:
        self.status_code = status
        self._data = data
        self.text = json.dumps(data)

    def json(self) -> Any:
        return self._data


class FakeCloud:
    """Routes (method, url regex) -> handler(params, body, token) -> (status, json)."""

    def __init__(self) -> None:
        self.routes: list[tuple[str, re.Pattern[str], Callable[..., Any]]] = []
        self.calls: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def on(self, method: str, pattern: str, handler: Callable[..., Any] | Any) -> None:
        fn = handler if callable(handler) else (lambda *_a, _h=handler: (200, _h))
        self.routes.insert(0, (method, re.compile(pattern), fn))

    def session(self) -> FakeCloud:
        return self

    def request(
        self,
        method: str,
        url: str,
        params: Any = None,
        json: Any = None,
        headers: Any = None,
        timeout: Any = None,
    ) -> FakeResponse:
        token = (headers or {}).get("Authorization", "").removeprefix("Bearer ")
        with self._lock:
            self.calls.append(
                {
                    "method": method,
                    "url": url,
                    "token": token,
                    "params": params,
                    "body": json,
                    "quota": (headers or {}).get("x-goog-user-project"),
                }
            )
        for m, rx, fn in self.routes:
            if m == method and rx.search(url):
                status, data = fn(params, json, token)
                return FakeResponse(status, data)
        return FakeResponse(
            404,
            {
                "error": {
                    "code": 404,
                    "message": f"no fake for {url}",
                    "status": "NOT_FOUND",
                }
            },
        )


def pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def register(c: TestClient, redirect: str = REDIRECT) -> str:
    r = c.post("/register", json={"redirect_uris": [redirect], "client_name": "Claude"})
    assert r.status_code == 201, r.text
    return str(r.json()["client_id"])


def _authorize(c: TestClient, client_id: str, redirect: str, challenge: str) -> str:
    r = c.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": redirect,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st8",
        },
        follow_redirects=False,
    )
    assert r.status_code in (200, 302), r.text
    if r.status_code == 200:
        assert "Continue with" in r.text
        return r.text.split('href="', 1)[1].split('"', 1)[0].replace("&amp;", "&")
    return str(r.headers["location"])


def sign_in(
    e: dict[str, Any],
    email: str,
    client_id: str | None = None,
    redirect: str = REDIRECT,
    hd: str | None = "ucr.edu",
    verified: bool = True,
) -> dict[str, Any]:
    """Run the whole OAuth flow; return the /token response (or the failure)."""
    c: TestClient = e["client"]
    client_id = client_id or register(c, redirect)
    verifier, challenge = pkce()
    google_url = _authorize(c, client_id, redirect, challenge)
    for _ in range(2):  # at most one consent retry
        g = urllib.parse.parse_qs(urllib.parse.urlsplit(google_url).query)
        assert g["hd"] == ["ucr.edu"]
        assert auth.GCP_SCOPE in g["scope"][0] and g["access_type"] == ["offline"]
        if "consent" in g["prompt"][0]:
            e["google"].consent_next = True
        claims: dict[str, Any] = {"email": email, "email_verified": verified}
        if hd is not None:
            claims["hd"] = hd
        e["google"].claims = claims
        r = c.get(
            "/oauth/callback",
            params={"state": g["state"][0], "code": "google-code"},
            follow_redirects=False,
        )
        if r.status_code == 302 and r.headers["location"].startswith(
            auth.GOOGLE_AUTHORIZE_URL
        ):
            e["consent_retries"] = e.get("consent_retries", 0) + 1
            google_url = r.headers["location"]
            continue
        break
    if r.status_code != 302:
        return {"status": r.status_code, "text": r.text}
    back = urllib.parse.parse_qs(urllib.parse.urlsplit(r.headers["location"]).query)
    assert back["state"] == ["st8"]
    r = c.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": back["code"][0],
            "code_verifier": verifier,
            "redirect_uri": redirect,
            "client_id": client_id,
        },
    )
    out = dict(r.json())
    out["status"] = r.status_code
    out["client_id"] = client_id
    return out


def rpc(
    c: TestClient, token: str, method: str, params: dict[str, Any] | None = None
) -> Any:
    r = c.post(
        "/mcp",
        headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
    )
    if r.status_code != 200:
        return r
    text = r.text
    if r.headers.get("content-type", "").startswith("text/event-stream"):
        data = [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")]
        text = data[-1]
    return json.loads(text)


def tool_names(c: TestClient, token: str) -> set[str]:
    res = rpc(c, token, "tools/list")
    return {t["name"] for t in res["result"]["tools"]}


def call(c: TestClient, token: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
    return dict(
        rpc(c, token, "tools/call", {"name": name, "arguments": args})["result"]
    )


def payload(res: dict[str, Any]) -> Any:
    assert not res.get("isError"), res
    return json.loads(res["content"][0]["text"])


def audit_lines(e: dict[str, Any]) -> list[dict[str, Any]]:
    out = e["capsys"].readouterr().out
    return [json.loads(ln) for ln in out.splitlines() if ln.startswith('{"severity"')]


@pytest.fixture
def cloud(monkeypatch: pytest.MonkeyPatch) -> FakeCloud:
    fake = FakeCloud()
    import skywalker.intel.gcp as gcpmod

    monkeypatch.setattr(gcpmod.requests, "Session", fake.session)
    real_init = gcpmod.Gcp.__init__

    def init(self: Any, *a: Any, **kw: Any) -> None:
        kw["session_factory"] = fake.session
        real_init(self, *a, **kw)

    monkeypatch.setattr(gcpmod.Gcp, "__init__", init)
    return fake


@pytest.fixture
def env(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], cloud: FakeCloud
) -> Iterator[dict[str, Any]]:
    import cache
    import server
    from app import build_app

    cache.clear()
    users_file = tmp_path / "users.yaml"
    users_file.write_text(USERS_YAML)
    google = FakeGoogle()
    seal_key = new_key()
    srv = auth.AuthServer(
        users=Users(str(users_file)),
        store=SealedStore(str(tmp_path / "data"), load_key(seal_key)),
        google=google,
        rev="abc1234",
        tools_version=server.TOOLS_VERSION,
    )
    client = TestClient(
        build_app(server.mcp, srv, quota_project="quota-proj"), base_url=BASE
    )
    client.__enter__()
    yield {
        "client": client,
        "server": srv,
        "google": google,
        "users_file": users_file,
        "tmp": tmp_path,
        "capsys": capsys,
        "cloud": cloud,
        "seal_key": seal_key,
    }
    client.__exit__(None, None, None)
    cache.clear()
