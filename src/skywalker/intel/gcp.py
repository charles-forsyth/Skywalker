"""A small Google Cloud REST client with explicit credentials, read-only by design.

Every call takes the caller's own OAuth access token (a string or a callable that
returns a fresh one), so two people using one process never share credentials:
there are no process-wide clients and nothing patches `google.auth`.

Read-only is enforced here, not by convention: GET is always allowed; POST only
for the read RPCs in `READ_POSTS` (getIamPolicy, Logging entries:list, BigQuery
SELECT queries). Every other method or URL raises `GcpError("refused")` before a
request leaves the process.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import requests

TokenSource = Callable[[], str]

# POST endpoints that only read. Everything else is refused.
READ_POSTS = (
    re.compile(
        r"^https://cloudresourcemanager\.googleapis\.com/v[13]/"
        r"(projects|folders|organizations)/[A-Za-z0-9._:-]+:getIamPolicy$"
    ),
    re.compile(r"^https://logging\.googleapis\.com/v2/entries:list$"),
    re.compile(
        r"^https://bigquery\.googleapis\.com/bigquery/v2/projects/[a-z0-9-]+/queries$"
    ),
)
_SELECT = re.compile(r"^\s*(SELECT|WITH)\b", re.IGNORECASE)
_WRITE_SQL = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|CALL|"
    r"EXPORT|LOAD|DECLARE|EXECUTE)\b",
    re.IGNORECASE,
)

RETRY_STATUS = (429, 500, 502, 503, 504)


class GcpError(Exception):
    """A Google API call failed. `kind` is one of: permission, api_disabled,
    not_found, invalid, quota, unavailable, auth, refused, timeout, error."""

    def __init__(self, kind: str, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.kind = kind
        self.status = status

    def as_dict(self) -> dict[str, Any]:
        return {"error": self.kind, "message": str(self)[:300]}


def _classify(status: int, body: Any) -> GcpError:
    err = body.get("error", {}) if isinstance(body, dict) else {}
    if not isinstance(err, dict):
        err = {"message": str(err)}
    msg = str(err.get("message") or f"HTTP {status}")
    reasons = " ".join(
        str(d.get("reason", "")) for d in err.get("details", []) if isinstance(d, dict)
    )
    text = f"{msg} {reasons} {err.get('status', '')}"
    if status == 401:
        return GcpError("auth", msg, status)
    if status == 403 and (
        "SERVICE_DISABLED" in text
        or "has not been used" in text
        or "is disabled" in text
    ):
        return GcpError("api_disabled", msg, status)
    if status == 403:
        return GcpError("permission", msg, status)
    if status == 404:
        return GcpError("not_found", msg, status)
    if status == 429:
        return GcpError("quota", msg, status)
    if status == 400:
        return GcpError("invalid", msg, status)
    if status >= 500:
        return GcpError("unavailable", msg, status)
    return GcpError("error", msg, status)


def check_read_only(method: str, url: str, body: dict[str, Any] | None) -> None:
    """Raise unless this request can only read."""
    base = url.split("?", 1)[0]
    if method == "GET":
        return
    if method != "POST" or not any(p.match(base) for p in READ_POSTS):
        raise GcpError("refused", f"{method} {base} is not a read-only call")
    if "bigquery.googleapis.com" in base:
        sql = str((body or {}).get("query", ""))
        if not _SELECT.match(sql) or _WRITE_SQL.search(sql) or ";" in sql:
            raise GcpError("refused", "only single SELECT statements may run")


class Gcp:
    """REST access to Google Cloud as one caller."""

    def __init__(
        self,
        token: TokenSource | str,
        quota_project: str | None = None,
        timeout: float = 30.0,
        session_factory: Callable[[], Any] = requests.Session,
    ) -> None:
        self._token: TokenSource = token if callable(token) else (lambda: token)
        self.quota_project = quota_project
        self.timeout = timeout
        self._session_factory = session_factory
        self._local = threading.local()
        self._skip_quota = False
        self.calls = 0

    def _session(self) -> Any:
        s = getattr(self._local, "session", None)
        if s is None:
            s = self._session_factory()
            self._local.session = s
        return s

    def request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | list[tuple[str, Any]] | None = None,
        body: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        check_read_only(method, url, body)
        attempt = 0
        while True:
            headers = {"Authorization": f"Bearer {self._token()}"}
            if self.quota_project and not self._skip_quota:
                headers["x-goog-user-project"] = self.quota_project
            self.calls += 1
            try:
                resp = self._session().request(
                    method,
                    url,
                    params=params,
                    json=body,
                    headers=headers,
                    timeout=timeout or self.timeout,
                )
            except requests.Timeout as e:
                raise GcpError("timeout", f"{url.split('?')[0]} timed out") from e
            except requests.RequestException as e:
                raise GcpError("unavailable", f"network error: {e}") from e
            status = resp.status_code
            if status == 200:
                try:
                    data = resp.json()
                except ValueError:
                    return {}
                return data if isinstance(data, dict) else {"value": data}
            try:
                payload = resp.json()
            except ValueError:
                payload = {"error": {"message": resp.text[:300]}}
            err = _classify(status, payload)
            if (
                status == 403
                and headers.get("x-goog-user-project")
                and (
                    "USER_PROJECT_DENIED" in str(payload)
                    or "serviceusage.services.use" in str(payload)
                )
            ):
                # The caller may not bill API quota to our project; use their own.
                self._skip_quota = True
                continue
            if status in RETRY_STATUS and attempt < 2:
                attempt += 1
                time.sleep(attempt)
                continue
            raise err

    def get(
        self, url: str, params: Any = None, timeout: float | None = None
    ) -> dict[str, Any]:
        return self.request("GET", url, params=params, timeout=timeout)

    def post(
        self, url: str, body: dict[str, Any], timeout: float | None = None
    ) -> dict[str, Any]:
        return self.request("POST", url, body=body, timeout=timeout)

    def paged(
        self,
        url: str,
        params: dict[str, Any] | None,
        key: str,
        limit: int = 1000,
        page_size_param: str = "pageSize",
        page_size: int = 500,
    ) -> Iterator[Any]:
        """Items under `key` across pages, at most `limit`."""
        p: dict[str, Any] = dict(params or {})
        p.setdefault(page_size_param, min(page_size, limit))
        seen = 0
        while True:
            data = self.get(url, p)
            for item in data.get(key, []) or []:
                yield item
                seen += 1
                if seen >= limit:
                    return
            tok = data.get("nextPageToken")
            if not tok:
                return
            p["pageToken"] = tok

    def aggregated(
        self, url: str, key: str, limit: int = 2000
    ) -> Iterator[tuple[str, Any]]:
        """Compute aggregatedList: (scope, item) across pages."""
        p: dict[str, Any] = {"maxResults": 500, "returnPartialSuccess": "true"}
        seen = 0
        while True:
            data = self.get(url, p)
            for scope, block in (data.get("items") or {}).items():
                for item in (block or {}).get(key, []) or []:
                    yield scope, item
                    seen += 1
                    if seen >= limit:
                        return
            tok = data.get("nextPageToken")
            if not tok:
                return
            p["pageToken"] = tok

    def query(
        self,
        job_project: str,
        sql: str,
        params: list[dict[str, Any]] | None = None,
        max_bytes: int = 10 * 1024**3,
        timeout_s: float = 90.0,
        max_rows: int = 50000,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Run one parameterized SELECT; return (rows, meta)."""
        body: dict[str, Any] = {
            "query": sql,
            "useLegacySql": False,
            "parameterMode": "NAMED",
            "queryParameters": params or [],
            "maximumBytesBilled": str(max_bytes),
            "timeoutMs": 20000,
            "maxResults": 10000,
        }
        url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{job_project}/queries"
        data = self.post(url, body, timeout=60)
        job = data.get("jobReference", {})
        deadline = time.monotonic() + timeout_s
        results_url = (
            f"https://bigquery.googleapis.com/bigquery/v2/projects/{job_project}"
            f"/queries/{job.get('jobId', '')}"
        )
        loc = {"location": job["location"]} if job.get("location") else {}
        while not data.get("jobComplete", False):
            if time.monotonic() > deadline:
                raise GcpError("timeout", "BigQuery query did not finish in time")
            data = self.get(
                results_url, {**loc, "timeoutMs": 10000, "maxResults": 10000}
            )
        fields = data.get("schema", {}).get("fields", [])
        rows = [_bq_row(fields, r) for r in data.get("rows", []) or []]
        tok = data.get("pageToken")
        while tok and len(rows) < max_rows:
            page = self.get(results_url, {**loc, "pageToken": tok, "maxResults": 10000})
            rows += [_bq_row(fields, r) for r in page.get("rows", []) or []]
            tok = page.get("pageToken")
        meta = {
            "bytes_processed": int(data.get("totalBytesProcessed", 0) or 0),
            "cache_hit": bool(data.get("cacheHit", False)),
            "rows": len(rows),
        }
        return rows, meta


def _bq_value(field: dict[str, Any], v: Any) -> Any:
    if v is None:
        return None
    t = field.get("type", "STRING")
    if field.get("mode") == "REPEATED":
        return [_bq_value({**field, "mode": "NULLABLE"}, x.get("v")) for x in v]
    if t in ("RECORD", "STRUCT"):
        return _bq_row(field.get("fields", []), v)
    if t in ("INTEGER", "INT64"):
        return int(v)
    if t in ("FLOAT", "FLOAT64", "NUMERIC", "BIGNUMERIC"):
        return float(v)
    if t in ("BOOLEAN", "BOOL"):
        return v in (True, "true", "TRUE")
    if t == "TIMESTAMP":
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(v)))
        except (TypeError, ValueError):
            return v
    return v


def _bq_row(fields: list[dict[str, Any]], row: dict[str, Any]) -> dict[str, Any]:
    cells = row.get("f", []) if isinstance(row, dict) else []
    return {
        f["name"]: _bq_value(f, c.get("v")) for f, c in zip(fields, cells, strict=False)
    }
