"""Shared helpers for the intel functions: config, input validation, time, money."""

from __future__ import annotations

import datetime as dt
import os
import re
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any
from zoneinfo import ZoneInfo

from .gcp import GcpError

PACIFIC = ZoneInfo("America/Los_Angeles")  # Cloud Billing's invoice time zone

_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_TABLE = re.compile(
    r"^[a-z][a-z0-9-]{4,28}[a-z0-9]\.[A-Za-z0-9_]{1,1024}\.[A-Za-z0-9_]{1,1024}$"
)
_BILLING = re.compile(r"^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$")
_SCOPE = re.compile(r"^(folders|organizations|projects)/[a-z0-9-]{1,40}$")
_EMAILISH = re.compile(r"^[A-Za-z0-9._%+@:-]{3,200}$")
_SERVICE = re.compile(r"^[a-z0-9.-]{3,100}$")
_MONTH = re.compile(r"^20[0-9]{2}-(0[1-9]|1[0-2])$")
_PROJECT_QUERY = re.compile(r"^[A-Za-z0-9 _.:*()=/-]{1,200}$")


@dataclass(frozen=True)
class IntelConfig:
    """Server-side settings. Nothing here comes from a caller."""

    billing_table: str = ""  # BigQuery billing export, project.dataset.table
    billing_account: str = ""  # e.g. XXXXXX-XXXXXX-XXXXXX
    job_project: str = ""  # project BigQuery jobs run (and bill) in
    fleet_scopes: tuple[str, ...] = ()  # folders/..., organizations/...
    domain: str = "ucr.edu"
    max_bytes: int = 10 * 1024**3  # per BigQuery query
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> IntelConfig:
        e = dict(os.environ if env is None else env)
        table = e.get("SKYWALKER_BILLING_TABLE", "").strip()
        acct = e.get("SKYWALKER_BILLING_ACCOUNT", "").strip()
        scopes = tuple(
            s.strip()
            for s in e.get("SKYWALKER_FLEET_SCOPES", "").split(",")
            if s.strip()
        )
        if table and not _TABLE.match(table):
            raise ValueError("SKYWALKER_BILLING_TABLE must be project.dataset.table")
        if acct and not _BILLING.match(acct):
            raise ValueError("SKYWALKER_BILLING_ACCOUNT looks wrong")
        for s in scopes:
            if not _SCOPE.match(s):
                raise ValueError(f"bad fleet scope {s!r}")
        job = e.get("SKYWALKER_JOB_PROJECT", "").strip()
        if job and not _PROJECT.match(job):
            raise ValueError("SKYWALKER_JOB_PROJECT is not a project id")
        return cls(
            billing_table=table,
            billing_account=acct,
            job_project=job,
            fleet_scopes=scopes,
            domain=e.get("SKYWALKER_DOMAIN", "ucr.edu").strip().lower() or "ucr.edu",
            max_bytes=int(e.get("SKYWALKER_MAX_BYTES", str(10 * 1024**3))),
        )


def project_id(value: str) -> str:
    v = (value or "").strip().lower()
    if not _PROJECT.match(v):
        raise GcpError("invalid", f"{value!r} is not a valid project id")
    return v


def emailish(value: str, what: str = "principal") -> str:
    v = (value or "").strip()
    if not _EMAILISH.match(v):
        raise GcpError("invalid", f"{what} {value!r} has unexpected characters")
    return v


def service_name(value: str) -> str:
    v = (value or "").strip().lower()
    if v and "." not in v:
        v += ".googleapis.com"
    if not _SERVICE.match(v):
        raise GcpError("invalid", f"{value!r} is not a service name")
    return v


def project_query(value: str) -> str:
    v = (value or "").strip()
    if not _PROJECT_QUERY.match(v):
        raise GcpError("invalid", "query may use letters, digits, spaces and _.:*()=/-")
    return v


def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(n)))


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(s: str | None) -> dt.datetime | None:
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def age_days(s: str | None, now: dt.datetime | None = None) -> int | None:
    t = parse_time(s)
    if t is None:
        return None
    return int(((now or now_utc()) - t).total_seconds() // 86400)


def period(
    days: int | None = None, month: str | None = None
) -> tuple[dt.datetime, dt.datetime, str]:
    """(start, end, label) in UTC for a billing window, Pacific-day aligned.

    Default is month to date. `month="2026-09"` is that whole month; `days=N` is
    the last N days up to now.
    """
    now = now_utc()
    local = now.astimezone(PACIFIC)
    if month:
        if not _MONTH.match(month):
            raise GcpError("invalid", "month must look like 2026-09")
        y, m = int(month[:4]), int(month[5:])
        start_l = dt.datetime(y, m, 1, tzinfo=PACIFIC)
        end_l = dt.datetime(y + (m == 12), m % 12 + 1, 1, tzinfo=PACIFIC)
        return (
            start_l.astimezone(dt.timezone.utc),
            min(end_l, local).astimezone(dt.timezone.utc),
            month,
        )
    if days:
        d = clamp(days, 1, 400)
        return now - dt.timedelta(days=d), now, f"last {d} days"
    start_l = dt.datetime(local.year, local.month, 1, tzinfo=PACIFIC)
    return start_l.astimezone(dt.timezone.utc), now, f"{local:%Y-%m} to date"


def money(units: Any = 0, nanos: Any = 0) -> float:
    try:
        return round(int(units or 0) + int(nanos or 0) / 1e9, 2)
    except (TypeError, ValueError):
        return 0.0


def r2(x: Any) -> float:
    try:
        return round(float(x or 0), 2)
    except (TypeError, ValueError):
        return 0.0


def basename(s: str | None) -> str:
    return (s or "").rstrip("/").rsplit("/", 1)[-1]


def zone_to_region(zone: str) -> str:
    return zone.rsplit("-", 1)[0] if zone.count("-") >= 2 else zone


def err(e: Exception) -> dict[str, Any]:
    if isinstance(e, GcpError):
        return e.as_dict()
    return {"error": "error", "message": f"{type(e).__name__}: {str(e)[:250]}"}


def sections(
    jobs: dict[str, Callable[[], Any]], workers: int = 8
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run independent sections in parallel; ({name: result}, {name: error})."""
    out: dict[str, Any] = {}
    errors: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(jobs)))) as ex:
        futs = {name: ex.submit(fn) for name, fn in jobs.items()}
        for name, f in futs.items():
            try:
                out[name] = f.result()
            except Exception as e:
                errors[name] = err(e)
    return out, errors


def parallel_map(
    fn: Callable[[Any], Any], items: Iterable[Any], workers: int = 12
) -> list[tuple[Any, Any, dict[str, Any] | None]]:
    """[(item, result, error)] keeping input order."""
    items = list(items)
    if not items:
        return []
    results: list[tuple[Any, Any, dict[str, Any] | None]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as ex:
        futs = [ex.submit(fn, it) for it in items]
        for it, f in zip(items, futs, strict=True):
            try:
                results.append((it, f.result(), None))
            except Exception as e:
                results.append((it, None, err(e)))
    return results


def top(items: list[Any], limit: int) -> tuple[list[Any], bool]:
    return items[:limit], len(items) > limit
