"""Per caller (person + client) answer cache and single-flight.

Nothing Skywalker returns is the same for every caller (each person sees only
what their own Google account can see), so answers are keyed by email AND
client, plus the tool and its arguments. A cached answer lives `ttl` seconds
(120 by default); tools take `fresh=true` to skip it. Identical calls from the
same caller that arrive while one is running share that one run. Errors are
never cached.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

DEFAULT_TTL = 120.0
MAX_ENTRIES = 2000

_entries: dict[str, tuple[float, Any]] = {}
_inflight: dict[str, asyncio.Future[Any]] = {}
_stats: dict[str, int] = {"hits": 0, "misses": 0, "joined": 0}


def key(email: str, client_id: str, tool: str, args: dict[str, Any]) -> str:
    return json.dumps([email, client_id, tool, args], sort_keys=True, default=str)


def clear() -> None:
    _entries.clear()


def forget_person(email: str) -> None:
    prefix = json.dumps([email])[:-1] + ","
    for k in [k for k in _entries if k.startswith(prefix)]:
        _entries.pop(k, None)


def stats() -> dict[str, int]:
    return {**_stats, "size": len(_entries)}


async def cached(
    k: str,
    fn: Callable[[], Awaitable[Any]],
    ttl: float = DEFAULT_TTL,
    fresh: bool = False,
) -> Any:
    now = time.monotonic()
    if not fresh:
        hit = _entries.get(k)
        if hit is not None and hit[0] > now:
            _stats["hits"] += 1
            return hit[1]
    running = _inflight.get(k)
    if running is not None:
        _stats["joined"] += 1
        return await asyncio.shield(running)
    _stats["misses"] += 1
    fut: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    _inflight[k] = fut
    try:
        value = await fn()
    except BaseException as e:
        fut.set_exception(e)
        fut.exception()
        raise
    else:
        fut.set_result(value)
        if ttl > 0:
            if len(_entries) >= MAX_ENTRIES:
                # Drop the entries closest to expiry.
                for old in sorted(_entries, key=lambda x: _entries[x][0])[
                    : MAX_ENTRIES // 4
                ]:
                    _entries.pop(old, None)
            _entries[k] = (time.monotonic() + ttl, value)
        return value
    finally:
        _inflight.pop(k, None)
