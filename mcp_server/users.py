"""Who may use the Skywalker MCP server, and with which role (`users.yaml`).

The file lives in Secret Manager (`skywalker-mcp-users`) and is mounted into the
container; it is re-read whenever it changes, so adding, removing or disabling a
person takes effect on their next request without a redeploy (the ursa-bifrost
model). Example::

    domain: ucr.edu
    users:
      - {email: forsythc@ucr.edu, netid: forsythc, role: admin,
         projects: [ucr-research-computing]}
      - {email: mikek@ucr.edu, netid: mikek, role: read,
         projects: [ucr-ursa-major-chen-lab, "ucr-ursa-major-chen-*"]}
    clients:              # pre-registered programs (Ultra, Atrium, ...)
      - id: skywalker-ultra
        name: Ultra
        max_role: staff
        calls_per_min: 300   # optional; default 60 (the person limit rises to match)
        redirect_uris: ["http://127.0.0.1/callback"]
    disabled_clients: []  # dynamic client ids (mcp_...) cut off, e.g. a lost laptop
    project_allocations:  # optional monthly allocations (USD) for read callers without central Billing IAM
      example-lab-project: 1000.0

Roles, lowest first: ``read`` < ``staff`` < ``admin``. A program client acts as the
person who signed it in, capped at its ``max_role``.

``projects`` (project ids, or a prefix ending in ``*``) is what a person looks at:

- ``read``: the only projects they may ask about. No list means no project.
- ``staff`` / ``admin``: any project their own Google account can see; the first
  exact id is their default focus (``skywalker_focus`` switches it, or to ``all``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
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
# A Google Cloud project id, optionally a prefix ending in "*".
_PROJECT_PAT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$|^[a-z][a-z0-9-]{0,28}\*$")
_EXACT_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class UsersFileError(ValueError):
    """users.yaml is missing or malformed."""


@dataclass(frozen=True)
class User:
    email: str
    netid: str
    role: str
    aliases: tuple[str, ...] = ()
    disabled: bool = False
    projects: tuple[str, ...] = ()
    allocations: dict[str, float] = field(default_factory=dict)


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
    # A confidential client (Gemini Enterprise's connector form sends a secret):
    # sha256 of the secret, checked at /token. None = public client (PKCE only).
    secret_sha256: str | None = None


@dataclass(frozen=True)
class UsersConfig:
    domain: str
    users: tuple[User, ...] = ()
    clients: tuple[ProgramClient, ...] = ()
    disabled_clients: frozenset[str] = frozenset()
    by_email: dict[str, User] = field(default_factory=dict)
    by_client: dict[str, ProgramClient] = field(default_factory=dict)
    project_allocations: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class UsageSnapshot:
    spend_this_month: float
    as_of: str = ""
    credits_this_month: float = 0.0
    net_this_month: float | None = None
    per_day_7d: float | None = None
    items: tuple[dict[str, Any], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "spend_this_month": self.spend_this_month,
            "as_of": self.as_of,
            "credits_this_month": self.credits_this_month,
            "net_this_month": self.net_this_month,
            "per_day_7d": self.per_day_7d,
            "items": list(self.items),
        }


@dataclass(frozen=True)
class ProjectFallback:
    project_id: str
    allocation: float | None = None
    usage: UsageSnapshot | None = None


def cap_role(role: str, ceiling: str | None) -> str:
    """The lower of two roles (ceiling None = no cap)."""
    if ceiling is None:
        return role
    return role if RANK[role] <= RANK[ceiling] else ceiling


def role_at_least(role: str, needed: str) -> bool:
    return RANK.get(role, -1) >= RANK[needed]


def project_allowed(patterns: tuple[str, ...], project: str) -> bool:
    """Whether a project id matches one of a person's ``projects`` entries."""
    for p in patterns:
        if p.endswith("*"):
            if project.startswith(p[:-1]):
                return True
        elif p == project:
            return True
    return False


def default_project(patterns: tuple[str, ...]) -> str:
    """The first exact project id in the list ("" if none)."""
    return next((p for p in patterns if not p.endswith("*")), "")


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


def _parse_allocations(raw_map: Any, where: str) -> dict[str, float]:
    if raw_map is None:
        return {}
    if not isinstance(raw_map, dict):
        raise UsersFileError(f"{where} must be a mapping")
    out: dict[str, float] = {}
    for k, v in raw_map.items():
        pid = str(k).strip().lower()
        if not _EXACT_PROJECT.match(pid):
            raise UsersFileError(f"{where}: project {k!r} is not valid")
        amt_raw = v.get("amount") if isinstance(v, dict) else v
        if (
            isinstance(amt_raw, bool)
            or not isinstance(amt_raw, (int, float))
            or not math.isfinite(float(amt_raw))
            or float(amt_raw) < 0
        ):
            raise UsersFileError(
                f"{where}[{pid!r}]: allocation must be a non-negative number"
            )
        out[pid] = round(float(amt_raw), 2)
    return out


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
        raw_projects = u.get("projects") or []
        if not isinstance(raw_projects, list):
            raise UsersFileError(f"users[{i}]: projects must be a list")
        projects = tuple(str(p).strip().lower() for p in raw_projects)
        for p in projects:
            if not _PROJECT_PAT.match(p):
                raise UsersFileError(f"users[{i}]: project {p!r} is not valid")
        user_allocs = _parse_allocations(
            u.get("allocations"), f"users[{i}].allocations"
        )
        user = User(
            email,
            netid,
            role,
            aliases,
            bool(u.get("disabled", False)),
            projects,
            user_allocs,
        )
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
        secret_sha = c.get("client_secret_sha256")
        if secret_sha is not None:
            secret_sha = str(secret_sha).strip().lower()
            if not _SHA256.match(secret_sha):
                raise UsersFileError(
                    f"clients[{i}]: client_secret_sha256 must be 64 hex characters"
                )
        raw_uris = c.get("redirect_uris")
        if raw_uris is not None and not isinstance(raw_uris, list):
            raise UsersFileError(f"clients[{i}]: redirect_uris must be a list")
        uris = tuple(str(x) for x in (raw_uris or []))
        if not all(valid_redirect(x) for x in uris):
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
            secret_sha,
        )
        clients.append(pc)
        by_client[cid] = pc
    disabled = frozenset(str(x).strip() for x in (raw.get("disabled_clients") or []))
    project_allocs = _parse_allocations(
        raw.get("project_allocations"), "project_allocations"
    )
    return UsersConfig(
        domain,
        tuple(users),
        tuple(clients),
        disabled,
        by_email,
        by_client,
        project_allocs,
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


def _finite_non_neg(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    f = float(value)
    if not math.isfinite(f) or f < 0:
        return None
    return round(f, 2)


def _finite_num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    f = float(value)
    if not math.isfinite(f):
        return None
    return round(f, 2)


def parse_usage(text: str) -> dict[str, UsageSnapshot]:
    """Parse pre-aggregated monthly project usage JSON (`SKYWALKER_PROJECT_USAGE_FILE`)."""
    raw = json.loads(text)
    if not isinstance(raw, dict):
        raise ValueError("usage JSON top level must be an object")
    top_as_of = str(raw.get("as_of") or "").strip()
    projects_raw = raw.get("projects")
    if not isinstance(projects_raw, dict):
        raise ValueError("usage JSON 'projects' must be an object")
    out: dict[str, UsageSnapshot] = {}
    for k, entry in projects_raw.items():
        pid = str(k).strip().lower()
        if not _EXACT_PROJECT.match(pid) or not isinstance(entry, dict):
            continue
        spend = _finite_non_neg(entry.get("spend_this_month"))
        if spend is None:
            continue
        cred = _finite_num(entry.get("credits_this_month")) or 0.0
        net = _finite_num(entry.get("net_this_month"))
        d7 = _finite_non_neg(entry.get("per_day_7d"))
        as_of = str(entry.get("as_of") or top_as_of).strip()
        raw_items = entry.get("items") or entry.get("services") or []
        items: list[dict[str, Any]] = []
        if isinstance(raw_items, list):
            for it in raw_items[:25]:
                if not isinstance(it, dict):
                    continue
                svc = str(it.get("service") or "").strip()
                g = _finite_non_neg(it.get("gross"))
                if not svc or g is None:
                    continue
                c = _finite_num(it.get("credits")) or 0.0
                n = _finite_num(it.get("net"))
                items.append(
                    {
                        "service": svc,
                        "gross": g,
                        "credits": c,
                        "net": n if n is not None else round(g + c, 2),
                    }
                )
        out[pid] = UsageSnapshot(
            spend_this_month=spend,
            as_of=as_of,
            credits_this_month=cred,
            net_this_month=net,
            per_day_7d=d7,
            items=tuple(items),
        )
    return out


class ProjectUsage:
    """Optional pre-aggregated monthly project usage file (`SKYWALKER_PROJECT_USAGE_FILE`)."""

    def __init__(self, path: str = "", recheck: float = 15.0) -> None:
        self.path = path
        self.recheck = recheck
        self._lock = threading.Lock()
        self._sig: tuple[float, int] | None = None
        self._digest = ""
        self._checked = 0.0
        self._data: dict[str, UsageSnapshot] = {}

    def _effective_path(self) -> str:
        return (self.path or os.environ.get("SKYWALKER_PROJECT_USAGE_FILE", "")).strip()

    def snapshots(self) -> dict[str, UsageSnapshot]:
        path = self._effective_path()
        if not path:
            return {}
        try:
            st = os.stat(path)
            sig = (st.st_mtime, st.st_size)
        except OSError:
            return self._data
        due = time.monotonic() - self._checked >= self.recheck
        if sig != self._sig or due:
            with self._lock:
                try:
                    st = os.stat(path)
                    with open(path, encoding="utf-8") as f:
                        text = f.read()
                except OSError as e:
                    logger.warning("usage file %s unreadable: %s", path, e)
                    return self._data
                self._sig = (st.st_mtime, st.st_size)
                self._checked = time.monotonic()
                digest = _digest(text)
                if digest != self._digest:
                    self._digest = digest
                    try:
                        self._data = parse_usage(text)
                    except (ValueError, TypeError) as e:
                        logger.error("usage file %s invalid: %s", path, e)
        return self._data

    def lookup(self, project: str) -> UsageSnapshot | None:
        return self.snapshots().get((project or "").strip().lower())


def project_fallback(
    role: str,
    allowed_projects: tuple[str, ...],
    pid: str,
    users: Users | None,
    usage: ProjectUsage | None = None,
    email: str = "",
) -> ProjectFallback | None:
    """Configured allocation and/or usage snapshot for `pid`, strictly gated by project_allowed for read callers."""
    norm = (pid or "").strip().lower()
    if not norm or not _EXACT_PROJECT.match(norm):
        return None
    if not role_at_least(role, "staff") and not project_allowed(allowed_projects, norm):
        return None
    alloc: float | None = None
    if users is not None:
        cfg = users.config()
        u = cfg.by_email.get((email or "").strip().lower()) if email else None
        if u is not None and norm in u.allocations:
            alloc = u.allocations[norm]
        elif norm in cfg.project_allocations:
            alloc = cfg.project_allocations[norm]
    snap = usage.lookup(norm) if usage is not None else None
    if alloc is None and snap is None:
        return None
    return ProjectFallback(project_id=norm, allocation=alloc, usage=snap)
