#!/usr/bin/env python3
"""Switch off each security guard in turn; the MCP tests must fail every time.

Prints CAUGHT, SURVIVED (a guard no test notices) or BROKEN (the pattern no longer
matches the source, e.g. after a reformat; update the pattern). Restores every
file afterwards, even on Ctrl-C. Run: uv run python scripts/mcp_mutation_check.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (file, original text, mutated text, what it guards)
MUTATIONS = [
    (
        "mcp_server/auth.py",
        '                    "scope": GCP_SCOPE,\n                },',
        "                },",
        "refresh narrowed to the cloud scope",
    ),
    (
        "mcp_server/auth.py",
        '        if access and set(str(tokens.get("scope", "")).split()) <= set(',
        '        if access or set(str(tokens.get("scope", "")).split()) <= set(',
        "broad sign-in token not used",
    ),
    (
        "src/skywalker/intel/gcp.py",
        'if method == "GET":\n        return',
        "if True:\n        return",
        "read-only: non-GET refused",
    ),
    (
        "src/skywalker/intel/gcp.py",
        'if not _SELECT.match(sql) or _WRITE_SQL.search(sql) or ";" in sql:',
        "if False:",
        "BigQuery SELECT-only",
    ),
    (
        "src/skywalker/intel/util.py",
        '    if not _PROJECT.match(v):\n        raise GcpError("invalid", f"{value!r} is not a valid project id")',
        "    pass",
        "project id validation",
    ),
    (
        "src/skywalker/intel/util.py",
        "    if not _EMAILISH.match(v):",
        "    if False:",
        "log filter input validation",
    ),
    (
        "src/skywalker/intel/billing.py",
        '        where += " AND project.id = @project"\n    key = GROUPS[group_by]',
        "        pass\n    key = GROUPS[group_by]",
        "spend scoped to the project",
    ),
    (
        "src/skywalker/intel/billing.py",
        '        where += " AND project.id = @project"\n    sql = (\n        "SELECT project.id AS project, project.number',
        '        pass\n    sql = (\n        "SELECT project.id AS project, project.number',
        "budget spend scoped to the project",
    ),
    (
        "mcp_server/access.py",
        "        if not role_at_least(ident.role, needed):",
        "        if False:",
        "role checked on each call",
    ),
    (
        "mcp_server/access.py",
        "            if t.name in TOOL_ROLES and role_at_least(ident.role, TOOL_ROLES[t.name])",
        "            if True",
        "tool list filtered by role",
    ),
    (
        "mcp_server/access.py",
        "        if needed is None:",
        "        if False:",
        "tool without a role refused",
    ),
    (
        "mcp_server/access.py",
        "        if not allowed:",
        "        if False:",
        "rate limit",
    ),
    (
        "mcp_server/auth.py",
        '        if str(claims.get("hd") or "").lower() != domain or not email.endswith(',
        "        if False and not email.endswith(",
        "hd/domain check",
    ),
    (
        "mcp_server/auth.py",
        '        if not claims.get("email_verified"):',
        "        if False:",
        "email_verified",
    ),
    (
        "mcp_server/auth.py",
        '        user = self.users.lookup(rec["email"])\n        if user is None:\n            # Removed',
        '        user = self.users.lookup(rec["email"]) or self.users.lookup("forsythc@ucr.edu")\n        if user is None:\n            # Removed',
        "removed user cut off",
    ),
    (
        "mcp_server/auth.py",
        '            if self.google_tokens.has(rec["email"]):\n                self.google_tokens.forget(rec["email"])',
        '            if False:\n                self.google_tokens.forget(rec["email"])',
        "removed user's Google grant revoked",
    ),
    (
        "mcp_server/auth.py",
        '        if not any(redirect_matches(r, ru) for r in client["redirect_uris"]):',
        "        if False:",
        "redirect URI must be registered",
    ),
    (
        "mcp_server/auth.py",
        "        if client is None:\n            # Unlike Nexus",
        "        if client is None and False:\n            # Unlike Nexus",
        "unknown client_id refused",
    ),
    (
        "mcp_server/auth.py",
        '        if GCP_SCOPE not in str(tokens.get("scope", "")).split():',
        "        if False:",
        "cloud scope required",
    ),
    (
        "mcp_server/auth.py",
        "            if not _verify_pkce(",
        "            if False and not _verify_pkce(",
        "PKCE",
    ),
    (
        "mcp_server/auth.py",
        '            if client_id and client_id != rec["client_id"]:\n                return _oauth_error(\n                    "invalid_grant", "refresh token belongs',
        '            if False:\n                return _oauth_error(\n                    "invalid_grant", "refresh token belongs',
        "refresh bound to client",
    ),
    (
        "mcp_server/auth.py",
        '            if self.store.pop("refresh", _hash(rt)) is None:',
        '            if self.store.get("refresh", _hash(rt)) is None:',
        "refresh rotation",
    ),
    (
        "mcp_server/auth.py",
        '                if str(e) == "reauth":\n                    self.forget(email, revoke=False)',
        "                if False:\n                    self.forget(email, revoke=False)",
        "dead grant forgotten (no loop)",
    ),
    (
        "mcp_server/auth.py",
        '        if rec["expires"] < time.time():',
        "        if False:",
        "access token expiry",
    ),
    (
        "mcp_server/cache.py",
        "    return json.dumps([email, client_id, tool, args], sort_keys=True, default=str)",
        "    return json.dumps([tool, args], sort_keys=True, default=str)",
        "cache keyed per person",
    ),
    (
        "mcp_server/auth.py",
        '                if rec.get("email") == ident.email:',
        "                if True:",
        "signout ends only the caller's sessions",
    ),
]


def run_tests() -> bool:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    r = subprocess.run(
        ["bash", str(ROOT / "scripts/test_mcp.sh"), "-x", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=600,
    )
    return r.returncode == 0


def main() -> int:
    backup = Path(tempfile.mkdtemp(prefix="sky-mut-"))
    files = sorted({m[0] for m in MUTATIONS})
    for f in files:
        (backup / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / f, backup / f)
    bad = 0
    try:
        if not run_tests():
            print("CONTROL FAILED: tests fail without any mutation")
            return 2
        print("control: tests pass")
        for f, old, new, what in MUTATIONS:
            path = ROOT / f
            text = (backup / f).read_text()
            if text.count(old) != 1:
                print(f"BROKEN    {what} ({f}: pattern found {text.count(old)}x)")
                bad += 1
                continue
            path.write_text(text.replace(old, new))
            for pc in ROOT.rglob("__pycache__"):
                shutil.rmtree(pc, ignore_errors=True)
            caught = not run_tests()
            path.write_text(text)
            print(f"{'CAUGHT   ' if caught else 'SURVIVED '} {what}")
            bad += 0 if caught else 1
    finally:
        for f in files:
            shutil.copy2(backup / f, ROOT / f)
        shutil.rmtree(backup, ignore_errors=True)
    print(f"{len(MUTATIONS) - bad}/{len(MUTATIONS)} guards caught")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
