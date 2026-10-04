"""Who may use the Skywalker MCP server, and with which role (`users.yaml`).

The file lives in Secret Manager (`skywalker-mcp-users`) and is mounted into the
container; it is re-read whenever it changes, so adding, removing or disabling a
person takes effect on their next request without a redeploy (the ursa-bifrost
model). Example::

    domain: ucr.edu
    users:
      - {email: forsythc@ucr.edu, netid: forsythc, role: admin}
      - {email: mikek@ucr.edu, netid: mikek, role: read}
    clients:              # pre-registered programs (Ultra, Atrium, ...)
      - id: skywalker-ultra
        name: Ultra
        max_role: staff
        calls_per_min: 300   # optional; default 60 (the person limit rises to match)
        redirect_uris: ["http://127.0.0.1/callback"]
    disabled_clients: []  # dynamic client ids (mcp_...) cut off, e.g. a lost laptop

Roles, lowest first: ``read`` < ``staff`` < ``admin``. A program client acts as the
person who signed it in, capped at its ``max_role``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import yaml  # type: ignore[import-untyped]

logger = logging.getLogger("skywalker-mcp.users")

ROLES = ("read", "staff", "admin")
# Upper bound for a program client's calls_per_min (one instance, 1 vCPU).
MAX_CALLS_PER_MIN = 600
RANK = {r: i for i, r in enumerate(ROLES)}

_NETID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_CLIENT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")


class UsersFileError(ValueError):
    """users.yaml is missing or malformed."""


@dataclass(frozen=True)
class User:
    email: str
    netid: str
    role: str
    aliases: tuple[str, ...] = ()
    disabled: bool = False


@dataclass(frozen=True)
class ProgramClient:
    id: str
    name: str
    max_role: str
    redirect_uris: tuple[str, ...] = ()
    disabled: bool = False
    # Calls per minute for this program (None = the server default). A program
    # that makes many small reads (Ultra) gets a larger budget than a chat client.
    calls_per_min: int | None = None


@dataclass(frozen=True)
class UsersConfig:
    domain: str
    users: tuple[User, ...] = ()
    clients: tuple[ProgramClient, ...] = ()
    disabled_clients: frozenset[str] = frozenset()
    by_email: dict[str, User] = field(default_factory=dict)
    by_client: dict[str, ProgramClient] = field(default_factory=dict)


def cap_role(role: str, ceiling: str | None) -> str:
    """The lower of two roles (ceiling None = no cap)."""
    if ceiling is None:
        return role
    return role if RANK[role] <= RANK[ceiling] else ceiling


def role_at_least(role: str, needed: str) -> bool:
    return RANK.get(role, -1) >= RANK[needed]


def valid_redirect(uri: str) -> bool:
    """https anywhere, or http on a loopback address (RFC 8252)."""
    try:
        u = urllib.parse.urlsplit(uri)
    except ValueError:
        return False
    if u.fragment or not u.hostname:
        return False
    if u.scheme == "https":
        return True
    return u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1")


def redirect_matches(registered: str, requested: str) -> bool:
    """Exact match, except the port of a loopback redirect may vary (RFC 8252 7.3)."""
    if registered == requested:
        return True
    a, b = urllib.parse.urlsplit(registered), urllib.parse.urlsplit(requested)
    loop = ("127.0.0.1", "localhost", "::1")
    return (
        a.scheme == b.scheme == "http"
        and a.hostname in loop
        and a.hostname == b.hostname
        and a.path == b.path
        and a.query == b.query
    )


def parse(text: str) -> UsersConfig:
    try:
        raw: Any = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        raise UsersFileError(f"not valid YAML: {e}") from e
    if not isinstance(raw, dict):
        raise UsersFileError("top level must be a mapping")
    domain = str(raw.get("domain") or "").strip().lower()
    if not domain or "." not in domain:
        raise UsersFileError("'domain' is required (e.g. ucr.edu)")
    users: list[User] = []
    by_email: dict[str, User] = {}
    for i, u in enumerate(raw.get("users") or []):
        if not isinstance(u, dict):
            raise UsersFileError(f"users[{i}] must be a mapping")
        email = str(u.get("email") or "").strip().lower()
        netid = str(u.get("netid") or "").strip().lower()
        role = str(u.get("role") or "read").strip().lower()
        aliases = tuple(str(a).strip().lower() for a in (u.get("aliases") or []))
        for addr in (email, *aliases):
            if not addr.endswith("@" + domain):
                raise UsersFileError(f"users[{i}]: {addr!r} is not in {domain}")
            if addr in by_email:
                raise UsersFileError(f"users[{i}]: {addr!r} is listed twice")
        if not _NETID.match(netid):
            raise UsersFileError(f"users[{i}]: netid {netid!r} is not valid")
        if role not in RANK:
            raise UsersFileError(f"users[{i}]: role must be one of {ROLES}")
        user = User(email, netid, role, aliases, bool(u.get("disabled", False)))
        users.append(user)
        for addr in (email, *aliases):
            by_email[addr] = user
    clients: list[ProgramClient] = []
    by_client: dict[str, ProgramClient] = {}
    for i, c in enumerate(raw.get("clients") or []):
        if not isinstance(c, dict):
            raise UsersFileError(f"clients[{i}] must be a mapping")
        cid = str(c.get("id") or "").strip()
        if not _CLIENT_ID.match(cid) or cid.startswith("mcp_"):
            raise UsersFileError(f"clients[{i}]: id {cid!r} is not valid")
        if cid in by_client:
            raise UsersFileError(f"clients[{i}]: id {cid!r} is listed twice")
        max_role = str(c.get("max_role") or "read").strip().lower()
        if max_role not in RANK:
            raise UsersFileError(f"clients[{i}]: max_role must be one of {ROLES}")
        cpm_raw = c.get("calls_per_min")
        cpm: int | None = None
        if cpm_raw is not None:
            if isinstance(cpm_raw, bool) or not isinstance(cpm_raw, int):
                raise UsersFileError(
                    f"clients[{i}]: calls_per_min must be a whole number"
                )
            if not 1 <= cpm_raw <= MAX_CALLS_PER_MIN:
                raise UsersFileError(
                    f"clients[{i}]: calls_per_min must be 1-{MAX_CALLS_PER_MIN}"
                )
            cpm = cpm_raw
        uris = tuple(str(x) for x in (c.get("redirect_uris") or []))
        if not uris or not all(valid_redirect(x) for x in uris):
            raise UsersFileError(
                f"clients[{i}]: redirect_uris must be https or http loopback"
            )
        pc = ProgramClient(
            cid,
            str(c.get("name") or cid)[:100],
            max_role,
            uris,
            bool(c.get("disabled", False)),
            cpm,
        )
        clients.append(pc)
        by_client[cid] = pc
    disabled = frozenset(str(x).strip() for x in (raw.get("disabled_clients") or []))
    return UsersConfig(
        domain, tuple(users), tuple(clients), disabled, by_email, by_client
    )


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class Users:
    """users.yaml, re-read when it changes.

    Checked on every call: a changed modification time or size triggers a
    re-read at once, and the content is re-read anyway every `recheck` seconds,
    because a Cloud Run secret mount can show a new secret version without a new
    modification time. A file that becomes unreadable or invalid keeps the last
    good copy in force and logs an error, so a typo in an edit does not lock
    everyone out; a file that is invalid at startup stops the server.
    """

    def __init__(self, path: str, recheck: float = 15.0) -> None:
        self.path = path
        self.recheck = recheck
        self._lock = threading.Lock()
        self._sig: tuple[float, int] | None = None
        self._digest = ""
        self._checked = 0.0
        text = self._read_text()
        self._cfg = parse(text)
        self._digest = _digest(text)

    def _read_text(self) -> str:
        try:
            st = os.stat(self.path)
            with open(self.path, encoding="utf-8") as f:
                text = f.read()
        except OSError as e:
            raise UsersFileError(f"cannot read {self.path}: {e}") from e
        self._sig = (st.st_mtime, st.st_size)
        self._checked = time.monotonic()
        return text

    def config(self) -> UsersConfig:
        try:
            st = os.stat(self.path)
            sig = (st.st_mtime, st.st_size)
        except OSError:
            logger.error("users file %s unreadable; keeping last good copy", self.path)
            return self._cfg
        due = time.monotonic() - self._checked >= self.recheck
        if sig != self._sig or due:
            with self._lock:
                try:
                    text = self._read_text()
                except UsersFileError as e:
                    logger.error("%s; keeping last good copy", e)
                    return self._cfg
                digest = _digest(text)
                if digest != self._digest:
                    # Remember the content even if it is bad, so a bad file is
                    # parsed (and logged) once, not on every call.
                    self._digest = digest
                    try:
                        self._cfg = parse(text)
                        logger.info(
                            "users file reloaded (%d users)", len(self._cfg.users)
                        )
                    except UsersFileError as e:
                        logger.error(
                            "users file invalid, keeping last good copy: %s", e
                        )
        return self._cfg

    @property
    def domain(self) -> str:
        return self.config().domain

    def lookup(self, email: str) -> User | None:
        """The enabled user for this email (or alias), else None."""
        user = self.config().by_email.get((email or "").strip().lower())
        if user is None or user.disabled:
            return None
        return user

    def program_client(self, client_id: str) -> ProgramClient | None:
        return self.config().by_client.get(client_id)
