"""
OAuth 2.1 authorization server for the Skywalker MCP server (the ursa-bifrost model,
ported from the Nexus MCP server).

People sign in with Google, restricted to the Workspace domain in users.yaml
(`hd=ucr.edu` on the Google request, and the ID token's `hd` and email domain
checked again in the callback). The server then issues its OWN opaque tokens:

- access tokens (1 h) and refresh tokens (30 days, rotated on every use, bound to
  the client that received them), stored hashed and sealed in `store.SealedStore`,
  so they survive restarts and redeploys;
- users.yaml is checked on every request, so removing or disabling a person (or a
  program client) takes effect on their next call;
- each request carries an `Identity` (email, NetID, effective role, client) in the
  ASGI scope for the MCP layer to authorize and audit.

Skywalker acts on Google Cloud AS THE CALLER. Sign-in also asks Google for the
`cloud-platform` scope with offline access; the person's Google refresh token is
sealed in the store (kind `google`, keyed by email) and access tokens are minted
from it on demand (`GoogleTokens.access_token`). The server itself only ever makes
read calls (skywalker.intel.gcp refuses anything else). Removing or disabling a
person deletes and revokes their Google token on their next request.

Endpoints:
  /.well-known/oauth-protected-resource[/mcp|/sse]  (MCP discovery, RFC 9728)
  /.well-known/oauth-authorization-server           (RFC 8414)
  /register                                         (RFC 7591 dynamic registration)
  /authorize                                        (code + PKCE S256)
  /oauth/callback                                   (Google upstream callback)
  /token                                            (code / refresh exchange)
  /revoke                                           (RFC 7009)
  /whoami                                           (who this token is; needs a token)
  /health                                           (liveness, build stamp)

Program clients in users.yaml are public (PKCE) unless they carry
`client_secret_sha256`. Gemini Enterprise is such a confidential client: its
connector forms send a client secret (in the body or as HTTP Basic), and its A2A
authorization URL carries no PKCE challenge, so a confidential client may skip
PKCE and must prove the secret at /token instead.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import json
import logging
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
from collections import deque
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

import httpx
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send
from store import SealedStore, load_key
from users import Users, cap_role, redirect_matches, valid_redirect

logger = logging.getLogger("skywalker-mcp.auth")

ACCESS_TOKEN_TTL = 3600  # 1 hour
REFRESH_TOKEN_TTL = 86400 * 30  # 30 days
GRANT_MAX_AGE = 86400 * 90  # 90 days absolute lifetime per sign-in grant
GRANT_WINDOW = 600  # an in-flight sign-in lives 10 minutes
SCOPE = "mcp"
IDENTITY_KEY = "skywalker.identity"  # ASGI scope key the MCP layer reads
SEEN_COOKIE = "skywalker_mcp_seen"
SEEN_COOKIE_MAX_AGE = 86400 * 90  # 90 days
CONSENT_CSRF_COOKIE = "skywalker_mcp_csrf"

GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
# What Skywalker asks Google for. cloud-platform is needed because the read-only
# scopes do not cover budgets, asset search, IAM, recommender, quotas or SCC; the
# server enforces read-only itself (skywalker.intel.gcp.check_read_only).
GCP_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
GOOGLE_SCOPES = f"openid email {GCP_SCOPE}"
# Never ask Google for incremental auth (include_granted_scopes): the OAuth client
# is shared with other UCR tools, and incremental auth folds every scope a person
# ever granted that client (Gmail, Drive, Calendar...) into Skywalker's grant.
# Access tokens are also minted with an explicit `scope` so they carry only
# GCP_SCOPE even when an older grant holds more.

PUBLIC_PATHS = {
    "/authorize",
    "/oauth/callback",
    "/token",
    "/register",
    "/revoke",
    "/health",
    # The A2A agent card is public (it names the sign-in endpoints); /a2a/ is not.
    "/a2a/.well-known/agent-card.json",
    "/a2a/.well-known/agent.json",
}


# --- Identity and audit -------------------------------------------------------


@dataclass(frozen=True)
class Identity:
    """Who is calling: the person, their effective role, and the client."""

    email: str
    netid: str
    role: str  # the person's role, capped by the client's max_role
    client_id: str
    client_name: str
    # A program client's own budget from users.yaml (None = server defaults).
    calls_per_min: int | None = None
    # users.yaml `projects`: for `read`, the only projects they may ask about;
    # for staff/admin, where their default focus comes from.
    projects: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def audit(event: str, **fields: Any) -> None:
    """One JSON line on stdout; Cloud Logging stores it as a structured entry."""
    decision = fields.get("decision", "")
    record = {
        "severity": "WARNING" if decision in ("denied", "error") else "INFO",
        "message": f"audit {event} {decision}".strip(),
        "audit": True,
        "event": event,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **fields,
    }
    print(json.dumps(record, default=str), file=sys.stdout, flush=True)


_SENSITIVE = ("token", "secret", "password", "key")


def redact_args(args: Mapping[str, Any] | None, limit: int = 200) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (args or {}).items():
        if any(s in k.lower() for s in _SENSITIVE):
            out[k] = "[redacted]"
        elif isinstance(v, str) and len(v) > limit:
            out[k] = f"{v[:limit]}...[{len(v)} chars]"
        else:
            out[k] = v
    return out


class RateLimiter:
    """n calls per window seconds per key (sliding window, in memory)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, n: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= n:
                return False
            q.append(now)
            return True


class InFlight:
    """At most n calls running at once per key (in memory).

    A rate limit counts calls per minute; this caps how many run at the same
    moment, so one runaway script (a loop firing calls without waiting) cannot
    hold the server's single process and database pool while everyone else
    waits. Over the cap a call is refused at once, not queued.
    """

    def __init__(self) -> None:
        self._n: dict[str, int] = {}
        self._lock = threading.Lock()

    def acquire(self, key: str, n: int) -> bool:
        with self._lock:
            cur = self._n.get(key, 0)
            if cur >= n:
                return False
            self._n[key] = cur + 1
            return True

    def release(self, key: str) -> None:
        with self._lock:
            cur = self._n.get(key, 0) - 1
            if cur > 0:
                self._n[key] = cur
            else:
                self._n.pop(key, None)

    def running(self, key: str) -> int:
        with self._lock:
            return self._n.get(key, 0)


# --- Google -------------------------------------------------------------------


class GoogleError(Exception):
    pass


class Google:
    """The upstream identity provider: code exchange plus ID-token verification."""

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret

    async def exchange(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """Exchange the code; return the verified ID-token claims.

        The Google tokens ride along under the private key `_tokens`
        (access_token, refresh_token, expires_in, scope)."""
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                },
            )
        if resp.status_code != 200:
            logger.error("Google token exchange failed: %s", resp.status_code)
            raise GoogleError("Google token exchange failed")
        data = resp.json()
        id_token_str = data.get("id_token", "")
        try:
            claims = await asyncio.to_thread(
                google_id_token.verify_oauth2_token,
                id_token_str,
                google_requests.Request(),
                self.client_id,
            )
        except Exception as e:
            logger.error("Google ID token verification failed: %s", e)
            raise GoogleError("invalid ID token") from e
        out = dict(claims)
        out["_tokens"] = {
            k: data.get(k)
            for k in ("access_token", "refresh_token", "expires_in", "scope")
        }
        return out

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        """A new access token from a refresh token (blocking; call in a thread).

        Raises GoogleError("reauth") when Google says the grant is gone
        (invalid_grant / invalid_rapt: revoked, expired, or the org's session
        policy wants a fresh sign-in)."""
        try:
            resp = httpx.post(
                GOOGLE_TOKEN_URL,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                    "scope": GCP_SCOPE,
                },
                timeout=15,
            )
        except httpx.HTTPError as e:
            raise GoogleError("Google token refresh failed (network)") from e
        if resp.status_code == 200:
            return dict(resp.json())
        try:
            err = str(resp.json().get("error", ""))
            sub = str(resp.json().get("error_subtype", ""))
        except ValueError:
            err, sub = "", ""
        if err in ("invalid_grant", "unauthorized_client") or sub == "invalid_rapt":
            raise GoogleError("reauth")
        raise GoogleError(f"Google token refresh failed ({resp.status_code})")

    def revoke(self, token: str) -> None:
        try:
            httpx.post(GOOGLE_REVOKE_URL, data={"token": token}, timeout=10)
        except httpx.HTTPError:
            logger.warning("Google token revoke failed (network)")


class GoogleTokens:
    """Each person's Google credentials, sealed in the store (kind `google`).

    `access_token(email)` returns a valid access token, refreshing under a
    per-person lock so concurrent tool calls make one refresh, not many. A dead
    grant deletes the record and raises GoogleError("reauth"), which the tools
    turn into "sign in again"; it never loops.
    """

    SKEW = 120  # refresh this many seconds before expiry

    def __init__(self, store: SealedStore, google: Google) -> None:
        self.store = store
        self.google = google
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()
        self._hot: dict[str, tuple[str, float]] = {}  # email -> (access, expires)

    def _lock(self, email: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(email, threading.Lock())

    def save(self, email: str, tokens: Mapping[str, Any]) -> bool:
        """Store tokens from a sign-in. Returns False when Google sent no refresh
        token and none is stored (the caller must ask for consent)."""
        old = self.store.get("google", email) or {}
        refresh = tokens.get("refresh_token") or old.get("refresh_token")
        if not refresh:
            return False
        rec = {
            "refresh_token": refresh,
            "scope": tokens.get("scope") or old.get("scope", ""),
            "saved": int(time.time()),
        }
        self.store.put("google", email, rec)
        access = tokens.get("access_token")
        # Use the sign-in's access token only when it carries nothing beyond what
        # Skywalker asked for; otherwise the first call mints a narrowed one.
        if access and set(str(tokens.get("scope", "")).split()) <= set(
            GOOGLE_SCOPES.split()
        ) | {"https://www.googleapis.com/auth/userinfo.email"}:
            with self._guard:
                self._hot[email] = (
                    str(access),
                    time.time() + float(tokens.get("expires_in") or 3600),
                )
        return True

    def has(self, email: str) -> bool:
        return self.store.get("google", email) is not None

    def scope(self, email: str) -> str:
        rec = self.store.get("google", email) or {}
        return str(rec.get("scope", ""))

    def access_token(self, email: str) -> str:
        with self._guard:
            hot = self._hot.get(email)
        if hot and hot[1] - self.SKEW > time.time():
            return hot[0]
        with self._lock(email):
            with self._guard:
                hot = self._hot.get(email)
            if hot and hot[1] - self.SKEW > time.time():
                return hot[0]
            rec = self.store.get("google", email)
            if rec is None:
                raise GoogleError("reauth")
            try:
                data = self.google.refresh(rec["refresh_token"])
            except GoogleError as e:
                if str(e) == "reauth":
                    self.forget(email, revoke=False)
                raise
            if (
                data.get("refresh_token")
                and data["refresh_token"] != rec["refresh_token"]
            ):
                rec["refresh_token"] = data["refresh_token"]
                self.store.put("google", email, rec)
            access = str(data.get("access_token", ""))
            exp = time.time() + float(data.get("expires_in") or 3600)
            with self._guard:
                self._hot[email] = (access, exp)
            return access

    def forget(self, email: str, revoke: bool = True) -> None:
        rec = self.store.pop("google", email)
        with self._guard:
            self._hot.pop(email, None)
        if revoke and rec and rec.get("refresh_token"):
            self.google.revoke(rec["refresh_token"])


# --- Helpers ------------------------------------------------------------------


def _verify_pkce(verifier: str, challenge: str) -> bool:
    if not verifier or not challenge:
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(expected, challenge)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _client_credentials(request: Request, form: Any) -> tuple[str, str]:
    """(client_id, client_secret) from HTTP Basic or the form body (RFC 6749 2.3.1)."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("basic "):
        try:
            raw = base64.b64decode(header[6:].strip()).decode()
            cid, _, sec = raw.partition(":")
            return urllib.parse.unquote_plus(cid), urllib.parse.unquote_plus(sec)
        except Exception:
            return "", ""
    return str(form.get("client_id", "")), str(form.get("client_secret", ""))


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        parts = [p.strip() for p in fwd.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return request.client.host if request.client else ""


_SAFE_HOST = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")


def _canonical_public_url(configured: str = "") -> str:
    raw = (
        (
            configured
            or os.environ.get("SKYWALKER_PUBLIC_URL")
            or os.environ.get("PUBLIC_URL")
            or ""
        )
        .strip()
        .rstrip("/")
    )
    if not raw:
        return ""
    u = urllib.parse.urlsplit(raw)
    if u.scheme not in ("https", "http") or not u.netloc:
        raise ValueError(f"invalid public URL {raw!r}")
    return f"{u.scheme}://{u.netloc}"


def _valid_http_url(raw: str) -> str:
    val = (raw or "").strip()
    if not val:
        return ""
    u = urllib.parse.urlsplit(val)
    if u.scheme in ("https", "http") and u.netloc and not u.fragment:
        return val
    return ""


def _atrium_url(configured: str = "") -> str:
    return _valid_http_url(
        configured
        or os.environ.get("ATRIUM_URL", "")
        or os.environ.get("SKYWALKER_ATRIUM_URL", "")
    )


def _wants_html(accept: str) -> bool:
    return "text/html" in (accept or "").lower()


def _scope_wants_html(scope: Scope) -> bool:
    for k, v in scope.get("headers", []):
        if k == b"accept":
            return _wants_html(v.decode("latin-1"))
    return False


def _seen_cookie_name(client_id: str, redirect_uri: str) -> str:
    host = (urllib.parse.urlsplit(redirect_uri).hostname or "").lower()
    digest = hashlib.sha256(f"{client_id}|{host}".encode()).hexdigest()[:16]
    return f"{SEEN_COOKIE}_{digest}"


def _oauth_error(kind: str, desc: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": kind, "error_description": desc},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


_RC_CSS = "body{margin:0;font-family:'Fira Sans','Helvetica Neue',Arial,sans-serif;color:#0f1b33;background:#f2f6fc;line-height:1.55}.u{background:#001a4f;color:#ccd8ed;font-size:13px;padding:6px 0}.u a{color:#ccd8ed;text-decoration:none;margin-right:18px}.t{background:#fff;border-bottom:1px solid #d5deec}.w{max-width:40rem;margin:0 auto;padding:0 1.25rem}.br{display:block;padding:14px 0;font-family:'Fira Sans Condensed','Fira Sans',Arial,sans-serif;font-weight:700;font-size:22px;color:#00287a;border-left:4px solid #ffb81c;padding-left:12px;margin:12px 0;line-height:1.1}.br small{display:block;font-family:'Fira Sans',Arial,sans-serif;font-weight:400;font-size:12px;color:#4b5874;margin-top:3px}.c{background:#fff;border:1px solid #d5deec;border-top:4px solid #003da5;border-radius:6px;padding:1.4rem 1.5rem;margin:2rem auto}h1{font-family:'Fira Sans Condensed','Fira Sans',Arial,sans-serif;font-size:1.6rem;color:#00287a;margin:0 0 .8rem}a{color:#1565c0}code{font-family:'Fira Code',ui-monospace,monospace;background:#eef1f6;padding:0 .3rem;border-radius:3px;word-break:break-all}a.b,button.b{display:inline-block;background:#003da5;color:#fff;padding:10px 18px;border-radius:4px;border:0;cursor:pointer;text-decoration:none;font-family:'Fira Sans Condensed','Fira Sans',Arial,sans-serif;font-weight:600;text-transform:uppercase;letter-spacing:.6px;font-size:14px}.n{background:#fffaf0;border-left:4px solid #ffb81c;padding:.6rem .9rem;border-radius:0 6px 6px 0}.bad{border-top-color:#b00020}.f{color:#4b5874;font-size:13px;text-align:center;padding:0 0 2rem}.f a{color:#4b5874}"


def _page(
    title: str, body: str, status: int = 200, atrium_url: str = ""
) -> HTMLResponse:
    """A page in the UCR Research Computing website look (inline styles: strict CSP)."""
    bad = " bad" if status >= 400 else ""
    t = html.escape(title)
    atrium = _atrium_url(atrium_url)
    atrium_nav = f'<a href="{html.escape(atrium)}">Atrium</a>' if atrium else ""
    return HTMLResponse(
        f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#00287a">
<title>{t} | Skywalker</title><style>{_RC_CSS}</style></head><body>
<div class="u"><div class="w"><a href="https://www.ucr.edu/">UCR Home</a><a href="https://ucr-research-computing.github.io/">Research Computing</a>{atrium_nav}</div></div>
<div class="t"><div class="w"><span class="br">Skywalker<small>UCR Research Computing</small></span></div></div>
<div class="w"><div class="c{bad}"><h1>{t}</h1>{body}</div>
<p class="f"><a href="https://ucr-research-computing.github.io/help/">Help from Research Computing</a></p></div>
</body></html>""",
        status_code=status,
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'",
        },
    )


# --- The authorization server --------------------------------------------------


class AuthServer:
    def __init__(
        self,
        users: Users,
        store: SealedStore,
        google: Google,
        rev: str = "",
        tools_version: str = "",
        public_url: str = "",
        atrium_url: str = "",
    ) -> None:
        self.users = users
        self.store = store
        self.google = google
        self.google_tokens = GoogleTokens(store, google)
        self.rev = rev
        self.tools_version = tools_version
        self.public_url = _canonical_public_url(public_url) if public_url else ""
        self.atrium_url = _valid_http_url(atrium_url)
        self.limiter = RateLimiter()
        self._access: dict[str, dict[str, Any]] = {}  # hash -> record (cache)
        self._revoked_grants: dict[str, float] = {}  # grant_id -> expires
        self._lock = threading.Lock()
        self._refresh_lock = threading.Lock()

    # -- clients ---------------------------------------------------------------

    def lookup_client(self, client_id: str) -> dict[str, Any] | None:
        """A pre-registered program client (users.yaml) or a registered dynamic one."""
        if not client_id:
            return None
        cfg = self.users.config()
        pc = cfg.by_client.get(client_id)
        if pc is not None:
            if pc.disabled:
                return None
            return {
                "client_id": pc.id,
                "client_name": pc.name,
                "redirect_uris": list(pc.redirect_uris),
                "max_role": pc.max_role,
                "calls_per_min": pc.calls_per_min,
                "program": True,
                "secret_sha256": pc.secret_sha256,
            }
        if client_id in cfg.disabled_clients:
            return None
        return self.store.get("client", client_id)

    # -- tokens ----------------------------------------------------------------

    def _issue(
        self,
        client_id: str,
        email: str,
        grant_id: str | None = None,
        grant_start: float | None = None,
    ) -> JSONResponse:
        now = time.time()
        gid = grant_id or secrets.token_urlsafe(24)
        gstart = grant_start if grant_start is not None else now
        max_exp = gstart + GRANT_MAX_AGE
        access_exp = min(now + ACCESS_TOKEN_TTL, max_exp)
        refresh_exp = min(now + REFRESH_TOKEN_TTL, max_exp)
        at = "swa_" + secrets.token_urlsafe(32)
        rt = "swr_" + secrets.token_urlsafe(32)
        access = {
            "email": email,
            "client_id": client_id,
            "grant_id": gid,
            "grant_start": gstart,
            "expires": access_exp,
        }
        self.store.put("access", _hash(at), access)
        with self._lock:
            self._access[_hash(at)] = access
        self.store.put(
            "refresh",
            _hash(rt),
            {
                "email": email,
                "client_id": client_id,
                "grant_id": gid,
                "grant_start": gstart,
                "expires": refresh_exp,
            },
        )
        return JSONResponse(
            {
                "access_token": at,
                "token_type": "Bearer",
                "expires_in": max(1, int(access_exp - now)),
                "refresh_token": rt,
                "scope": SCOPE,
            },
            headers={"Cache-Control": "no-store"},
        )

    def _grant_revoked(self, grant_id: str) -> bool:
        if not grant_id:
            return False
        now = time.time()
        with self._lock:
            exp = self._revoked_grants.get(grant_id)
            if exp is not None:
                if exp >= now:
                    return True
                self._revoked_grants.pop(grant_id, None)
        rec = self.store.get("grantrevoked", grant_id)
        if rec is None:
            return False
        with self._lock:
            self._revoked_grants[grant_id] = float(
                rec.get("expires") or (now + REFRESH_TOKEN_TTL)
            )
        return True

    def _revoke_grant(
        self,
        grant_id: str,
        email: str = "",
        client_id: str = "",
        reason: str = "revoke",
    ) -> None:
        if not grant_id:
            return
        exp = time.time() + GRANT_MAX_AGE
        self.store.put(
            "grantrevoked",
            grant_id,
            {
                "email": email,
                "client_id": client_id,
                "reason": reason,
                "expires": exp,
            },
        )
        with self._lock:
            self._revoked_grants[grant_id] = exp
            for h in [
                h for h, r in self._access.items() if r.get("grant_id") == grant_id
            ]:
                self._access.pop(h, None)
        for kind in ("access", "refresh"):
            for name, r in list(self.store.items(kind)):
                if r.get("grant_id") == grant_id:
                    self.store.delete_name(kind, name)
        audit(
            "grant_revoked",
            email=email or None,
            client=client_id or None,
            decision="revoked",
            reason=reason,
        )

    def _access_record(self, token: str) -> dict[str, Any] | None:
        h = _hash(token)
        with self._lock:
            rec = self._access.get(h)
        if rec is None:
            rec = self.store.get("access", h)
            if rec is None:
                return None
            with self._lock:
                self._access[h] = rec
        if rec["expires"] < time.time():
            with self._lock:
                self._access.pop(h, None)
            return None
        gstart = rec.get("grant_start")
        if isinstance(gstart, (int, float)) and time.time() - gstart > GRANT_MAX_AGE:
            with self._lock:
                self._access.pop(h, None)
            return None
        gid = str(rec.get("grant_id") or "")
        if gid and self._grant_revoked(gid):
            with self._lock:
                self._access.pop(h, None)
            return None
        return rec

    def resolve(self, token: str) -> tuple[Identity | None, str]:
        """(identity, "") or (None, "invalid_token" | "access_denied")."""
        rec = self._access_record(token)
        if rec is None:
            return None, "invalid_token"
        user = self.users.lookup(rec["email"])
        if user is None:
            # Removed or disabled: their Google grant goes too (once).
            if self.google_tokens.has(rec["email"]):
                self.google_tokens.forget(rec["email"])
                audit(
                    "google_token",
                    email=rec["email"],
                    decision="revoked",
                    reason="user_removed",
                )
            return None, "access_denied"
        client = self.lookup_client(rec["client_id"])
        if client is None:
            return None, "access_denied"
        role = cap_role(user.role, client.get("max_role"))
        return (
            Identity(
                email=user.email,
                netid=user.netid,
                role=role,
                client_id=client["client_id"],
                client_name=str(client.get("client_name") or ""),
                calls_per_min=client.get("calls_per_min")
                if client.get("program")
                else None,
                projects=user.projects,
            ),
            "",
        )

    # -- discovery ---------------------------------------------------------------

    def base_url(self, request: Request) -> str:
        pub = _canonical_public_url(self.public_url)
        if pub:
            return pub
        # Never trust X-Forwarded-Host: Cloud Run passes client-supplied headers through.
        proto = (
            request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
        )
        if proto not in ("https", "http"):
            proto = (
                request.url.scheme
                if request.url.scheme in ("https", "http")
                else "https"
            )
        host = (
            request.headers.get("host") or request.url.netloc or "localhost"
        ).strip()
        if not _SAFE_HOST.match(host):
            host = request.url.netloc or "localhost"
        return f"{proto}://{host}"

    async def home(self, request: Request) -> Response:
        base = self.base_url(request)
        domain = self.users.domain
        if not _wants_html(request.headers.get("accept", "")):
            return PlainTextResponse(
                f"skywalker-mcp: MCP endpoint at {base}/mcp (OAuth 2.1, {domain})\n"
            )
        atrium = _atrium_url(self.atrium_url)
        atrium_line = (
            f'<p>Prefer a web dashboard? Open <a href="{html.escape(atrium)}">Atrium</a> '
            "to view your cloud projects alongside your other Research Computing resources.</p>"
            if atrium
            else ""
        )
        stamp = []
        if self.rev:
            stamp.append(f"rev <code>{html.escape(self.rev)}</code>")
        if self.tools_version:
            stamp.append(f"tools v{html.escape(self.tools_version)}")
        stamp_line = (
            f'<p class="n">Read-only service ({", ".join(stamp)}).</p>'
            if stamp
            else '<p class="n">Read-only service: Skywalker never modifies Google Cloud resources.</p>'
        )
        return _page(
            "Skywalker MCP server",
            f"""<p>This is the Model Context Protocol (MCP) server for <b>Skywalker</b>,
read-only Google Cloud audit, cost and security reporting.</p>
<p>Add this MCP server URL in your AI client (Claude, Gemini, Hermes):</p>
<p><code>{html.escape(base)}/mcp</code></p>
<p>You sign in with your <b>{html.escape(domain)}</b> Google account, and every tool
reads Google Cloud as you. Only accounts on the Skywalker access list can sign in.</p>
{atrium_line}{stamp_line}""",
            atrium_url=atrium,
        )

    async def protected_resource(self, request: Request) -> JSONResponse:
        base = self.base_url(request)
        return JSONResponse(
            {
                "resource": base,
                "authorization_servers": [base],
                "bearer_methods_supported": ["header"],
                "scopes_supported": [SCOPE],
            }
        )

    async def authorization_server(self, request: Request) -> JSONResponse:
        base = self.base_url(request)
        return JSONResponse(
            {
                "issuer": base,
                "authorization_endpoint": f"{base}/authorize",
                "token_endpoint": f"{base}/token",
                "registration_endpoint": f"{base}/register",
                "revocation_endpoint": f"{base}/revoke",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": [
                    "none",
                    "client_secret_post",
                    "client_secret_basic",
                ],
                "revocation_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": [SCOPE],
            }
        )

    # -- registration --------------------------------------------------------------

    async def register(self, request: Request) -> JSONResponse:
        if not self.limiter.allow("register:" + _client_ip(request), 10):
            return _oauth_error("slow_down", "too many registrations", 429)
        try:
            body = await request.json()
        except Exception:
            return _oauth_error("invalid_client_metadata", "bad JSON")
        if not isinstance(body, dict):
            return _oauth_error("invalid_client_metadata", "bad JSON")
        uris = body.get("redirect_uris")
        if not isinstance(uris, list) or not 1 <= len(uris) <= 5:
            return _oauth_error("invalid_redirect_uri", "1-5 redirect_uris required")
        for u in uris:
            if not isinstance(u, str) or not valid_redirect(u):
                return _oauth_error(
                    "invalid_redirect_uri",
                    f"redirect URIs must be https or http loopback: {u}",
                )
        method = body.get("token_endpoint_auth_method") or "none"
        if method != "none":
            return _oauth_error(
                "invalid_client_metadata",
                "only public clients (auth method none) with PKCE",
            )
        name = str(body.get("client_name") or "MCP client")[:100]
        client_id = "mcp_" + secrets.token_urlsafe(16)
        now = int(time.time())
        record = {
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": uris,
            "created": now,
        }
        self.store.put("client", client_id, record)
        audit("register", client=client_id, client_name=name, decision="allowed")
        return JSONResponse(
            {
                "client_id": client_id,
                "client_id_issued_at": now,
                "client_name": name,
                "redirect_uris": uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
            status_code=201,
        )

    # -- authorize -----------------------------------------------------------------

    async def authorize(self, request: Request) -> Response:
        if request.method == "POST":
            return await self._authorize_confirm(request)
        p = request.query_params
        client_id = p.get("client_id", "")
        ru = p.get("redirect_uri", "")
        client = self.lookup_client(client_id)
        if client is None:
            # Unlike Nexus, never adopt an unknown client_id: the old Skywalker
            # server's in-memory registrations are gone, and adopting would let any
            # caller pick its own redirect URI. Clients re-register (RFC 7591).
            return PlainTextResponse(
                "unknown client_id; register again", status_code=400
            )
        if not any(redirect_matches(r, ru) for r in client["redirect_uris"]):
            # Never redirect to an unregistered URI.
            return PlainTextResponse(
                "redirect_uri is not registered for this client", status_code=400
            )

        def fail(kind: str, desc: str) -> Response:
            params = {"error": kind, "error_description": desc}
            if p.get("state"):
                params["state"] = p["state"]
            sep = "&" if "?" in ru else "?"
            return RedirectResponse(f"{ru}{sep}{urllib.parse.urlencode(params)}", 302)

        if p.get("response_type") != "code":
            return fail("unsupported_response_type", "code only")
        confidential = bool(client.get("secret_sha256"))
        # PKCE is required of public clients; a confidential client (secret
        # checked at /token) may use it too, and then it is checked.
        if (p.get("code_challenge") or not confidential) and (
            not p.get("code_challenge") or p.get("code_challenge_method") != "S256"
        ):
            return fail("invalid_request", "PKCE with S256 is required")

        pending = {
            "client_id": client["client_id"],
            "redirect_uri": ru,
            "code_challenge": p.get("code_challenge", ""),
            "state": p.get("state", ""),
            "expires": time.time() + GRANT_WINDOW,
        }
        # Only pre-registered program clients may skip consent when this browser has
        # already confirmed the exact (client_id, redirect_hostname) pair. Dynamically
        # registered RFC 7591 clients always require explicit POST confirmation.
        seen_name = _seen_cookie_name(client["client_id"], ru)
        if client.get("program") and request.cookies.get(seen_name) == "1":
            return RedirectResponse(
                self._google_url(request, pending, consent=False), 302
            )
        consent_id = secrets.token_urlsafe(24)
        csrf = secrets.token_urlsafe(24)
        self.store.put("consent", consent_id, {**pending, "csrf": csrf})
        host = urllib.parse.urlsplit(ru).hostname or ru
        domain = self.users.domain
        dcr_note = (
            ""
            if client.get("program")
            else '<p class="n">This client registered dynamically (not a pre-registered campus service). '
            "Continue only if you just started this sign-in from that app.</p>"
        )
        resp = _page(
            "Sign in to Skywalker",
            f"""<p><b>{html.escape(str(client.get("client_name") or "An MCP client"))}</b>
wants to use the Skywalker MCP server as you.</p>
<p>You will sign in with your <b>{html.escape(domain)}</b> Google account. Afterwards
you are sent back to <code>{html.escape(host)}</code>.</p>
{dcr_note}<p>Skywalker reads your Google Cloud projects <b>as you</b>: it sees only what your
own account can see, and Google's audit logs show your name. Google will ask you to
allow Cloud Platform access; Skywalker only reads (it has no tools that change
anything), and you can sign out at any time to delete its copy of your access.</p>
<p>Only people on the Skywalker access list can finish signing in. Skywalker never
sees your Google password.</p>
<form method="post" action="/authorize">
<input type="hidden" name="consent" value="{html.escape(consent_id)}">
<input type="hidden" name="csrf" value="{html.escape(csrf)}">
<p><button class="b" type="submit">Continue with Google</button></p>
</form>""",
            atrium_url=self.atrium_url,
        )
        resp.set_cookie(
            CONSENT_CSRF_COOKIE,
            csrf,
            max_age=GRANT_WINDOW,
            path="/authorize",
            httponly=True,
            secure=self.base_url(request).startswith("https://"),
            samesite="lax",
        )
        return resp

    async def _authorize_confirm(self, request: Request) -> Response:
        base = self.base_url(request)
        origin = request.headers.get("origin", "").strip().rstrip("/")
        if origin and origin != base.rstrip("/"):
            return PlainTextResponse("cross-origin consent refused", status_code=403)
        try:
            form = await request.form()
        except Exception:
            return PlainTextResponse("form body required", status_code=400)
        consent_id = str(form.get("consent", ""))
        rec = self.store.pop("consent", consent_id) if consent_id else None
        if rec is None:
            return PlainTextResponse(
                "invalid or expired consent; start again", status_code=400
            )
        cookie_csrf = request.cookies.get(CONSENT_CSRF_COOKIE, "")
        form_csrf = str(form.get("csrf", ""))
        want_csrf = str(rec.get("csrf", ""))
        if (
            not want_csrf
            or not cookie_csrf
            or not secrets.compare_digest(cookie_csrf, want_csrf)
            or not secrets.compare_digest(form_csrf, want_csrf)
        ):
            return PlainTextResponse(
                "invalid consent session; start again", status_code=403
            )
        client = self.lookup_client(str(rec.get("client_id", "")))
        if client is None:
            return PlainTextResponse(
                "unknown client_id; register again", status_code=400
            )
        pending = {k: v for k, v in rec.items() if k != "csrf"}
        google_url = self._google_url(request, pending, consent=False)
        resp = RedirectResponse(google_url, 302)
        secure = base.startswith("https://")
        resp.delete_cookie(CONSENT_CSRF_COOKIE, path="/authorize")
        if client.get("program"):
            resp.set_cookie(
                _seen_cookie_name(client["client_id"], str(pending["redirect_uri"])),
                "1",
                max_age=SEEN_COOKIE_MAX_AGE,
                path="/authorize",
                httponly=True,
                secure=secure,
                samesite="lax",
            )
        return resp

    def _google_url(
        self, request: Request, pending: dict[str, Any], consent: bool
    ) -> str:
        """Store the pending sign-in under a fresh state; return Google's URL.

        `select_account` normally; `consent` only on the one retry when Google
        returned no refresh token and none is stored (Google issues refresh
        tokens only on a consent screen)."""
        upstream_state = secrets.token_urlsafe(24)
        self.store.put("pending", upstream_state, {**pending, "consent": consent})
        return (
            GOOGLE_AUTHORIZE_URL
            + "?"
            + urllib.parse.urlencode(
                {
                    "client_id": self.google.client_id,
                    "redirect_uri": f"{self.base_url(request)}/oauth/callback",
                    "response_type": "code",
                    "scope": GOOGLE_SCOPES,
                    "state": upstream_state,
                    "access_type": "offline",
                    "prompt": "consent select_account" if consent else "select_account",
                    "hd": self.users.domain,
                }
            )
        )

    # -- Google callback -----------------------------------------------------------

    async def oauth_callback(self, request: Request) -> Response:
        q = request.query_params
        state = q.get("state", "")
        pending = self.store.pop("pending", state) if state else None
        if q.get("error"):
            return PlainTextResponse(
                f"Google sign-in error: {q['error']}", status_code=400
            )
        if not q.get("code") or pending is None:
            return PlainTextResponse("invalid or expired sign-in; start again", 400)
        try:
            claims = await self.google.exchange(
                q["code"], f"{self.base_url(request)}/oauth/callback"
            )
        except GoogleError as e:
            return PlainTextResponse(str(e), status_code=400)

        domain = self.users.domain
        email = str(claims.get("email") or "").lower()

        def deny(reason: str, message: str) -> HTMLResponse:
            audit(
                "signin",
                email=email,
                client=pending["client_id"],
                decision="denied",
                reason=reason,
            )
            return _page(
                "Access denied",
                f"<p>{message}</p><p>If you think this is wrong, contact "
                '<a href="mailto:forsythc@ucr.edu">forsythc@ucr.edu</a>.</p>',
                status=403,
                atrium_url=self.atrium_url,
            )

        if not claims.get("email_verified"):
            return deny(
                "email_not_verified", "Google has not verified this email address."
            )
        if str(claims.get("hd") or "").lower() != domain or not email.endswith(
            "@" + domain
        ):
            return deny(
                "wrong_domain",
                f"Sign in with your <b>{html.escape(domain)}</b> account. "
                f"<code>{html.escape(email)}</code> is not one.",
            )
        user = self.users.lookup(email)
        if user is None:
            return deny(
                "not_on_list",
                f"<code>{html.escape(email)}</code> is not on the Skywalker access list.",
            )
        if self.lookup_client(pending["client_id"]) is None:
            return PlainTextResponse("client is no longer registered", status_code=400)
        tokens = claims.get("_tokens") or {}
        if GCP_SCOPE not in str(tokens.get("scope", "")).split():
            return deny(
                "scope_not_granted",
                "Skywalker needs Cloud Platform access to read your projects. Start "
                "again and leave that box ticked on Google's screen.",
            )
        if not self.google_tokens.save(user.email, tokens):
            if pending.get("consent"):
                return deny(
                    "no_refresh_token", "Google did not return an offline grant."
                )
            # Google only issues a refresh token on a consent screen: ask once more.
            return RedirectResponse(
                self._google_url(request, pending, consent=True), 302
            )

        code = secrets.token_urlsafe(32)
        self.store.put(
            "code",
            code,
            {
                "client_id": pending["client_id"],
                "redirect_uri": pending["redirect_uri"],
                "code_challenge": pending["code_challenge"],
                "email": user.email,
                "expires": time.time() + GRANT_WINDOW,
            },
        )
        audit(
            "signin", email=user.email, client=pending["client_id"], decision="allowed"
        )
        params = {"code": code}
        if pending["state"]:
            params["state"] = pending["state"]
        ru = pending["redirect_uri"]
        sep = "&" if "?" in ru else "?"
        return RedirectResponse(f"{ru}{sep}{urllib.parse.urlencode(params)}", 302)

    # -- token -----------------------------------------------------------------------

    async def token(self, request: Request) -> JSONResponse:
        if not self.limiter.allow("token:" + _client_ip(request), 60):
            return _oauth_error("slow_down", "too many token requests", 429)
        try:
            form = await request.form()
        except Exception:
            return _oauth_error("invalid_request", "form body required")
        grant = str(form.get("grant_type", ""))
        client_id, client_secret = _client_credentials(request, form)

        if grant == "authorization_code":
            rec = self.store.pop("code", str(form.get("code", "")))
            if rec is None:
                return _oauth_error("invalid_grant", "code unknown, used or expired")
            if client_id and client_id != rec["client_id"]:
                return _oauth_error(
                    "invalid_grant", "code was issued to another client"
                )
            sent_ru = str(form.get("redirect_uri", ""))
            if sent_ru != rec["redirect_uri"] and not (
                # A confidential client that proves its secret may leave it out.
                not sent_ru and self._confidential(rec["client_id"])
            ):
                return _oauth_error("invalid_grant", "redirect_uri mismatch")
            secret_err = self._check_secret(rec["client_id"], client_secret)
            if secret_err:
                return secret_err
            if rec["code_challenge"] and not _verify_pkce(
                str(form.get("code_verifier", "")), rec["code_challenge"]
            ):
                return _oauth_error("invalid_grant", "PKCE verification failed")
            if not rec["code_challenge"] and not self._confidential(rec["client_id"]):
                return _oauth_error("invalid_grant", "PKCE verification failed")
            if self.users.lookup(rec["email"]) is None:
                return _oauth_error("invalid_grant", "user is no longer allowed")
            return self._issue(
                rec["client_id"],
                rec["email"],
                grant_id=secrets.token_urlsafe(24),
                grant_start=time.time(),
            )

        if grant == "refresh_token":
            rt = str(form.get("refresh_token", ""))
            if not rt:
                return _oauth_error("invalid_grant", "refresh token unknown or expired")
            with self._refresh_lock:
                rec = self.store.get("refresh", _hash(rt))
                if rec is None:
                    used = self.store.get("refreshused", _hash(rt))
                    if used is not None:
                        self._revoke_grant(
                            str(used.get("grant_id") or ""),
                            str(used.get("email") or ""),
                            str(used.get("client_id") or ""),
                            reason="refresh_reuse",
                        )
                    return _oauth_error(
                        "invalid_grant", "refresh token unknown or expired"
                    )
                now = time.time()
                gid = str(rec.get("grant_id") or "")
                gstart = rec.get("grant_start")
                if (gid and self._grant_revoked(gid)) or (
                    isinstance(gstart, (int, float)) and now - gstart > GRANT_MAX_AGE
                ):
                    self.store.delete("refresh", _hash(rt))
                    return _oauth_error(
                        "invalid_grant",
                        "grant expired or revoked; sign in again",
                    )
                # Bound to its client: client_id is always required on refresh_token.
                if not client_id or client_id != rec["client_id"]:
                    return _oauth_error(
                        "invalid_grant", "refresh token belongs to another client"
                    )
                secret_err = self._check_secret(rec["client_id"], client_secret)
                if secret_err:
                    return secret_err
                if self.store.pop("refresh", _hash(rt)) is None:  # rotate; lost race
                    return _oauth_error("invalid_grant", "refresh token already used")
                if gid:
                    self.store.put(
                        "refreshused",
                        _hash(rt),
                        {
                            "email": rec["email"],
                            "client_id": rec["client_id"],
                            "grant_id": gid,
                            "expires": max(
                                float(rec["expires"]), now + REFRESH_TOKEN_TTL
                            ),
                        },
                    )
            email, cid = rec["email"], rec["client_id"]
            if self.users.lookup(email) is None:
                audit(
                    "refresh",
                    email=email,
                    client=cid,
                    decision="denied",
                    reason="not_on_list",
                )
                return _oauth_error("invalid_grant", "user is no longer allowed")
            if self.lookup_client(cid) is None:
                audit(
                    "refresh",
                    email=email,
                    client=cid,
                    decision="denied",
                    reason="client_not_allowed",
                )
                return _oauth_error("invalid_grant", "client is not allowed")
            return self._issue(
                cid,
                email,
                grant_id=gid or None,
                grant_start=float(gstart) if isinstance(gstart, (int, float)) else now,
            )

        return _oauth_error(
            "unsupported_grant_type", "authorization_code or refresh_token"
        )

    def _confidential(self, client_id: str) -> bool:
        client = self.lookup_client(client_id)
        return bool(client and client.get("secret_sha256"))

    def _check_secret(self, client_id: str, secret: str) -> JSONResponse | None:
        """None if the client is public or proved its secret; else the error."""
        client = self.lookup_client(client_id)
        want = (client or {}).get("secret_sha256")
        if not want:
            return None
        got = hashlib.sha256(secret.encode()).hexdigest() if secret else ""
        if not secrets.compare_digest(got, str(want)):
            audit("token", client=client_id, decision="denied", reason="bad_secret")
            return _oauth_error("invalid_client", "client authentication failed", 401)
        return None

    # -- revoke, whoami, health ------------------------------------------------------

    async def revoke(self, request: Request) -> Response:
        if not self.limiter.allow("revoke:" + _client_ip(request), 60):
            return _oauth_error("slow_down", "too many requests", 429)
        try:
            form = await request.form()
        except Exception:
            return Response(status_code=200)
        raw_tok = str(form.get("token", ""))
        if not raw_tok:
            return Response(status_code=200)
        h = _hash(raw_tok)
        rec = self.store.get("access", h) or self.store.get("refresh", h)
        if rec is None:
            with self._lock:
                rec = self._access.get(h)
        with self._lock:
            self._access.pop(h, None)
        self.store.delete("access", h)
        self.store.delete("refresh", h)
        if rec and rec.get("grant_id"):
            self._revoke_grant(
                str(rec["grant_id"]),
                str(rec.get("email") or ""),
                str(rec.get("client_id") or ""),
                reason="revoke",
            )
        return Response(status_code=200)  # RFC 7009: always 200

    async def signout(self, request: Request) -> JSONResponse:
        """Forget and revoke the caller's Google grant and end every session.

        Needs a valid access token. The person signs in again to use Skywalker."""
        ident: Identity | None = request.scope.get(IDENTITY_KEY)
        if ident is None:
            return _oauth_error("invalid_token", "no identity", 401)
        await asyncio.to_thread(self.google_tokens.forget, ident.email)
        ended = 0
        for kind in ("access", "refresh", "refreshused"):
            for name, rec in list(self.store.items(kind)):
                if rec.get("email") == ident.email:
                    self.store.delete_name(kind, name)
                    if kind in ("access", "refresh"):
                        ended += 1
        with self._lock:
            for h in [
                h for h, r in self._access.items() if r.get("email") == ident.email
            ]:
                self._access.pop(h, None)
        audit(
            "signout",
            email=ident.email,
            client=ident.client_id,
            decision="allowed",
            ended=ended,
        )
        return JSONResponse({"signed_out": ident.email, "tokens_ended": ended})

    async def whoami(self, request: Request) -> JSONResponse:
        ident: Identity | None = request.scope.get(IDENTITY_KEY)
        if ident is None:
            return _oauth_error("invalid_token", "no identity", 401)
        return JSONResponse(
            {
                **ident.as_dict(),
                "rev": self.rev,
                "google_token": self.google_tokens.has(ident.email),
                "google_scope": self.google_tokens.scope(ident.email),
            }
        )

    async def health(self, _: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "rev": self.rev,
                "tools_version": self.tools_version,
            }
        )

    @property
    def routes(self) -> list[Route]:
        prm = self.protected_resource
        return [
            Route("/", self.home, methods=["GET", "HEAD"]),
            Route("/.well-known/oauth-protected-resource", prm),
            Route("/.well-known/oauth-protected-resource/mcp", prm),
            Route("/.well-known/oauth-protected-resource/sse", prm),
            Route("/.well-known/oauth-authorization-server", self.authorization_server),
            Route("/register", self.register, methods=["POST"]),
            Route("/authorize", self.authorize, methods=["GET", "POST"]),
            Route("/oauth/callback", self.oauth_callback),
            Route("/token", self.token, methods=["POST"]),
            Route("/revoke", self.revoke, methods=["POST"]),
            Route("/whoami", self.whoami),
            Route("/signout", self.signout, methods=["POST"]),
            Route("/health", self.health),
        ]


# --- Bearer middleware (pure ASGI, so SSE streams pass through untouched) -------


class BearerAuth:
    def __init__(self, app: ASGIApp, auth: AuthServer) -> None:
        self.app = app
        self.auth = auth

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in PUBLIC_PATHS or path.startswith("/.well-known/"):
            await self.app(scope, receive, send)
            return
        if (
            path == "/"
            and scope.get("method") in ("GET", "HEAD")
            and _scope_wants_html(scope)
        ):
            await self.app(scope, receive, send)
            return
        header = ""
        for k, v in scope.get("headers", []):
            if k == b"authorization":
                header = v.decode("latin-1")
                break
        if not header.lower().startswith("bearer "):
            await self._challenge(scope, receive, send, "invalid_request")
            return
        ident, err = self.auth.resolve(header[7:].strip())
        if ident is None:
            if err == "access_denied":
                audit("request", path=path, decision="denied", reason="access_denied")
                resp = JSONResponse(
                    {
                        "error": "access_denied",
                        "error_description": "not on the Skywalker access list, or disabled",
                    },
                    status_code=403,
                )
                await resp(scope, receive, send)
                return
            await self._challenge(scope, receive, send, "invalid_token")
            return
        scope[IDENTITY_KEY] = ident
        await self.app(scope, receive, send)

    async def _challenge(
        self, scope: Scope, receive: Receive, send: Send, error: str
    ) -> None:
        request = Request(scope)
        resource = f"{self.auth.base_url(request)}/.well-known/oauth-protected-resource"
        resp = Response(
            status_code=401,
            headers={
                "WWW-Authenticate": (
                    f'Bearer realm="skywalker-mcp", error="{error}", '
                    f'resource_metadata="{resource}"'
                )
            },
        )
        await resp(scope, receive, send)


# --- Construction ---------------------------------------------------------------


def build_auth_from_env(
    env: Mapping[str, str] = os.environ, tools_version: str = ""
) -> AuthServer:
    missing = [
        k
        for k in (
            "GOOGLE_OAUTH_CLIENT_ID",
            "GOOGLE_OAUTH_CLIENT_SECRET",
            "MCP_SEAL_KEY",
        )
        if not env.get(k)
    ]
    if missing:
        raise RuntimeError(
            f"Skywalker MCP server missing env vars: {missing}. See README.md."
        )
    return AuthServer(
        users=Users(env.get("SKYWALKER_MCP_USERS", "/users/users.yaml")),
        store=SealedStore(
            env.get("SKYWALKER_MCP_DATA", "/data"), load_key(env["MCP_SEAL_KEY"])
        ),
        google=Google(env["GOOGLE_OAUTH_CLIENT_ID"], env["GOOGLE_OAUTH_CLIENT_SECRET"]),
        rev=env.get("SKYWALKER_REV", ""),
        tools_version=tools_version,
        public_url=env.get("SKYWALKER_PUBLIC_URL") or env.get("PUBLIC_URL") or "",
        atrium_url=env.get("ATRIUM_URL") or env.get("SKYWALKER_ATRIUM_URL") or "",
    )
