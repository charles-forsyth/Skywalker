"""Per-call authorization and audit for the Skywalker MCP tools.

`GuardedMCP` is FastMCP with two changes:

- `list_tools` shows a caller only the tools their role allows, so a `read`
  user never sees a write tool;
- `call_tool` checks the role again (a client can call a tool it was never
  shown), caps how many calls one caller has running at once, applies a
  per-person and per-client rate limit, and writes one audit line per call:
  who, which client, tool, redacted arguments, decision, time.

Every tool must be registered with `guarded_tool(role=...)`. A tool without a
role is refused for everyone (`TOOL_ROLES` is the allowlist), so a new tool is
never exposed by accident.

The caller's identity comes from the ASGI scope, put there by `auth.BearerAuth`.
The A2A agent (agent.py) runs tools in-process with `acting_as(identity)`, so its
calls pass the same role check, limits and audit as MCP calls (`channel=a2a`).
Skywalker tools act on Google Cloud as the caller, so a tool asks
`caller_gcp()` for a `skywalker.intel.Gcp` built on the caller's own Google token.
There is no stdio identity: without a signed-in caller there is no Google token.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable, Iterator, Sequence
from contextvars import ContextVar
from typing import Any

from auth import (
    IDENTITY_KEY,
    GoogleError,
    GoogleTokens,
    Identity,
    InFlight,
    RateLimiter,
    audit,
    redact_args,
)
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ContentBlock, TextContent, ToolAnnotations
from mcp.types import Tool as MCPTool
from store import SealedStore
from users import RANK, role_at_least

from skywalker.intel import Gcp, GcpError

# tool name -> lowest role that may call it
TOOL_ROLES: dict[str, str] = {}

# Set only by agent.py (inside one A2A request, from the identity BearerAuth put
# in the ASGI scope): the person the agent's in-process tool calls run as.
_ACTING: ContextVar[Identity | None] = ContextVar("skywalker_acting", default=None)
_CHANNEL: ContextVar[str] = ContextVar("skywalker_channel", default="mcp")

# Each Skywalker call fans out to many Google API calls as the caller, so the
# budgets are lower than Nexus's: 120/min per person, 60/min per client, and 8
# running at once per caller.
CALLS_PER_MIN_PERSON = 120
CALLS_PER_MIN_CLIENT = 60
MAX_IN_FLIGHT = 8


def read_only(title: str) -> ToolAnnotations:
    # openWorldHint: results come from Google Cloud, outside this server.
    return ToolAnnotations(
        title=title, readOnlyHint=True, idempotentHint=True, openWorldHint=True
    )


def setting(title: str) -> ToolAnnotations:
    # Changes only a Skywalker setting of the caller's (never Google Cloud).
    return ToolAnnotations(
        title=title,
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )


def write(title: str, destructive: bool = False) -> ToolAnnotations:
    return ToolAnnotations(
        title=title,
        readOnlyHint=False,
        destructiveHint=destructive,
        idempotentHint=False,
        openWorldHint=False,
    )


class GuardedMCP(FastMCP):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.limiter = RateLimiter()
        self.in_flight = InFlight()
        self.google_tokens: GoogleTokens | None = None  # set by app.build_app
        self.quota_project: str | None = None
        self.store: SealedStore | None = None  # set by app.build_app (focus)

    def caller_gcp(self, ident: Identity) -> Gcp:
        """Google Cloud access as this caller (their own token, refreshed on demand)."""
        tokens = self.google_tokens
        if tokens is None:
            raise ToolError("server is not configured for Google access")
        email = ident.email

        def token() -> str:
            try:
                return tokens.access_token(email)
            except GoogleError as e:
                if str(e) == "reauth":
                    raise GcpError(
                        "auth",
                        "your Google sign-in has expired or was revoked; sign in to "
                        "Skywalker again (your MCP client's reconnect/login)",
                    ) from e
                raise GcpError("unavailable", str(e)) from e

        return Gcp(token, quota_project=self.quota_project)

    def guarded_tool(
        self, role: str, annotations: ToolAnnotations
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        if role not in RANK:
            raise ValueError(f"unknown role {role!r}")

        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            TOOL_ROLES[fn.__name__] = role
            return self.tool(annotations=annotations)(fn)

        return deco

    @contextlib.contextmanager
    def acting_as(self, ident: Identity, channel: str = "a2a") -> Iterator[None]:
        """Run tool calls in-process as this person (the A2A agent)."""
        t1, t2 = _ACTING.set(ident), _CHANNEL.set(channel)
        try:
            yield
        finally:
            _ACTING.reset(t1)
            _CHANNEL.reset(t2)

    def identity(self) -> Identity | None:
        acting = _ACTING.get()
        if acting is not None:
            return acting
        try:
            req = self._mcp_server.request_context.request
        except LookupError:
            req = None
        if req is not None:
            ident = getattr(req, "scope", {}).get(IDENTITY_KEY)
            return ident if isinstance(ident, Identity) else None
        return None

    async def list_tools(self) -> list[MCPTool]:
        ident = self.identity()
        tools = await super().list_tools()
        if ident is None:
            return []
        return [
            t
            for t in tools
            if t.name in TOOL_ROLES and role_at_least(ident.role, TOOL_ROLES[t.name])
        ]

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> Sequence[ContentBlock] | dict[str, Any]:
        ident = self.identity()
        start = time.monotonic()
        base = {
            "tool": name,
            "args": redact_args(arguments),
            "email": ident.email if ident else None,
            "netid": ident.netid if ident else None,
            "role": ident.role if ident else None,
            "client": ident.client_id if ident else None,
            "client_name": ident.client_name if ident else None,
            "channel": _CHANNEL.get(),
        }
        needed = TOOL_ROLES.get(name)
        if ident is None:
            audit("tool", **base, decision="denied", reason="no_identity")
            raise ToolError("not signed in")
        if needed is None:
            audit("tool", **base, decision="denied", reason="unknown_tool")
            raise ToolError(f"unknown tool {name!r}")
        if not role_at_least(ident.role, needed):
            audit("tool", **base, decision="denied", reason=f"needs_{needed}")
            raise ToolError(
                f"{name} needs the '{needed}' role; you have '{ident.role}'"
                + (
                    f" through client {ident.client_name or ident.client_id}"
                    if ident.client_id
                    else ""
                )
                + "."
            )
        # The in-flight key matches the budget key: a program client for one
        # person, or the person's own clients together.
        flight_key = (
            "pc:" + ident.client_id + ":" + ident.email
            if ident.calls_per_min
            else "p:" + ident.email
        )
        if not self.in_flight.acquire(flight_key, MAX_IN_FLIGHT):
            audit("tool", **base, decision="denied", reason="busy")
            raise ToolError(
                f"{MAX_IN_FLIGHT} of your calls are still running; wait for one"
                " to finish and try again"
            )
        try:
            return await self._limited_call(name, arguments, ident, base, start)
        finally:
            self.in_flight.release(flight_key)

    async def _limited_call(
        self,
        name: str,
        arguments: dict[str, Any],
        ident: Identity,
        base: dict[str, Any],
        start: float,
    ) -> Sequence[ContentBlock] | dict[str, Any]:
        if ident.calls_per_min:
            # A program client with its own budget (users.yaml calls_per_min) is
            # limited by that budget alone: it neither starves nor is starved by
            # the person's chat clients, which keep the person limit below.
            # Keyed per person too: two people signed in to the same program
            # each get the budget.
            allowed = self.limiter.allow(
                "pc:" + ident.client_id + ":" + ident.email, ident.calls_per_min
            )
        else:
            allowed = self.limiter.allow(
                "p:" + ident.email, CALLS_PER_MIN_PERSON
            ) and self.limiter.allow("c:" + ident.client_id, CALLS_PER_MIN_CLIENT)
        if not allowed:
            audit("tool", **base, decision="denied", reason="rate_limited")
            raise ToolError("too many calls; wait a minute and try again")
        try:
            result = await super().call_tool(name, arguments)
        except Exception as e:
            audit(
                "tool",
                **base,
                decision="error",
                error=type(e).__name__,
                ms=int((time.monotonic() - start) * 1000),
            )
            raise
        audit(
            "tool",
            **base,
            decision="allowed",
            ms=int((time.monotonic() - start) * 1000),
            result_chars=_result_chars(result),
        )
        return result


def _result_chars(result: Any) -> int:
    try:
        blocks = result[0] if isinstance(result, tuple) else result
        return sum(len(b.text) for b in blocks if isinstance(b, TextContent))
    except Exception:
        return -1
