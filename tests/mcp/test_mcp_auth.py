"""Sign-in, roles, Google tokens, isolation between callers, and audit."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any

import access
import auth
import pytest
from conftest import (
    BASE,
    REDIRECT,
    USERS_YAML,
    FakeGoogle,
    audit_lines,
    call,
    payload,
    pkce,
    register,
    rpc,
    sign_in,
    tool_names,
)
from starlette.testclient import TestClient
from store import SealedStore, load_key
from users import Users

READ_TOOLS = {
    "skywalker_whoami",
    "skywalker_projects",
    "skywalker_overview",
    "skywalker_spend",
    "skywalker_budget",
    "skywalker_inventory",
    "skywalker_compute",
    "skywalker_recommendations",
    "skywalker_access",
    "skywalker_service_accounts",
    "skywalker_api_keys",
    "skywalker_exposure",
    "skywalker_activity",
    "skywalker_services",
    "skywalker_api_traffic",
    "skywalker_quotas",
    "skywalker_focus",
}
# Tools that change only a Skywalker setting of the caller's (never Google Cloud).
SETTING_TOOLS = {"skywalker_focus"}
STAFF_TOOLS = {
    "skywalker_fleet",
    "skywalker_spend_all",
    "skywalker_budgets",
    "skywalker_spend_trend",
}


def _project_route(cloud: Any) -> None:
    cloud.on(
        "GET",
        r"cloudresourcemanager\.googleapis\.com/v3/projects:search",
        lambda p, b, t: (
            200,
            {
                "projects": [
                    {
                        "projectId": "lab-one-proj",
                        "name": "projects/111",
                        "displayName": "Lab One",
                        "parent": "folders/9",
                    }
                ]
            },
        ),
    )


# --- sign-in and roles -----------------------------------------------------------


def test_admin_sees_every_tool_and_read_user_only_read_tools(
    env: dict[str, Any],
) -> None:
    c = env["client"]
    admin = sign_in(env, "forsythc@ucr.edu")
    assert admin["status"] == 200 and admin["access_token"].startswith("swa_")
    assert tool_names(c, admin["access_token"]) == READ_TOOLS | STAFF_TOOLS
    mike = sign_in(env, "mikek@ucr.edu")["access_token"]
    assert tool_names(c, mike) == READ_TOOLS
    res = call(c, mike, "skywalker_fleet", {})
    assert res["isError"] and "needs the 'staff' role" in res["content"][0]["text"]


def test_every_tool_is_read_only_and_has_a_role() -> None:
    import server

    tools = server.mcp._tool_manager.list_tools()
    names = {t.name for t in tools}
    assert names == READ_TOOLS | STAFF_TOOLS
    for t in tools:
        assert t.name in access.TOOL_ROLES, t.name
        assert t.annotations is not None, t.name
        if t.name in SETTING_TOOLS:
            assert t.annotations.openWorldHint is False, t.name
        else:
            assert t.annotations.readOnlyHint is True, t.name
        assert t.annotations.destructiveHint in (None, False), t.name


@pytest.mark.parametrize(
    "email,hd,verified",
    [
        ("someone@gmail.com", None, True),
        ("someone@ucr.edu", "other.edu", True),
        ("forsythc@ucr.edu", None, True),
        ("forsythc@ucr.edu", "ucr.edu", False),
        ("nobody@ucr.edu", "ucr.edu", True),
        ("gone@ucr.edu", "ucr.edu", True),
    ],
)
def test_sign_in_refusals(
    env: dict[str, Any], email: str, hd: Any, verified: bool
) -> None:
    out = sign_in(env, email, hd=hd, verified=verified)
    assert out["status"] == 403
    assert any(
        ln["event"] == "signin" and ln["decision"] == "denied"
        for ln in audit_lines(env)
    )
    # a refused person never gets a stored Google token
    assert not env["server"].google_tokens.has(email.lower())


def test_sign_in_needs_the_cloud_scope(env: dict[str, Any]) -> None:
    env["google"].scope = "openid email"  # person unticked Cloud Platform
    out = sign_in(env, "forsythc@ucr.edu")
    assert out["status"] == 403 and "Cloud Platform" in out["text"]
    assert not env["server"].google_tokens.has("forsythc@ucr.edu")


def test_refresh_token_only_on_first_grant_triggers_one_consent_retry(
    env: dict[str, Any],
) -> None:
    first = sign_in(env, "forsythc@ucr.edu")
    assert first["status"] == 200 and env.get("consent_retries", 0) == 0
    # Lose the stored grant (e.g. signed out); Google won't resend a refresh token
    # without the consent screen, so the server asks once with prompt=consent.
    env["server"].google_tokens.forget("forsythc@ucr.edu", revoke=False)
    again = sign_in(env, "forsythc@ucr.edu")
    assert again["status"] == 200 and env["consent_retries"] == 1
    assert env["server"].google_tokens.has("forsythc@ucr.edu")


def test_second_sign_in_keeps_the_stored_grant_without_consent(
    env: dict[str, Any],
) -> None:
    sign_in(env, "forsythc@ucr.edu")
    sign_in(env, "forsythc@ucr.edu")  # no refresh token this time; stored one is kept
    assert env.get("consent_retries", 0) == 0
    assert env["server"].google_tokens.has("forsythc@ucr.edu")


def test_google_token_is_sealed_at_rest(env: dict[str, Any]) -> None:
    sign_in(env, "forsythc@ucr.edu")
    files = list((env["tmp"] / "data" / "google").iterdir())
    assert len(files) == 1
    raw = files[0].read_bytes()
    assert b"gr-forsythc" not in raw and b"forsythc" not in raw
    assert "forsythc" not in files[0].name


def test_removed_user_is_cut_off_and_google_grant_revoked(env: dict[str, Any]) -> None:
    tok = sign_in(env, "mikek@ucr.edu")
    c = env["client"]
    assert "skywalker_overview" in tool_names(c, tok["access_token"])
    f: Path = env["users_file"]
    f.write_text(
        USERS_YAML.replace(
            "netid: mikek, role: read", "netid: mikek, role: read, disabled: true"
        )
    )
    os.utime(f, (time.time() + 5, time.time() + 5))
    assert rpc(c, tok["access_token"], "tools/list").status_code == 403
    assert not env["server"].google_tokens.has("mikek@ucr.edu")
    assert "gr-mikek@ucr.edu" in env["google"].revoked
    r = c.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tok["refresh_token"],
            "client_id": tok["client_id"],
        },
    )
    assert r.status_code == 400


def test_role_change_takes_effect_without_new_sign_in(env: dict[str, Any]) -> None:
    tok = sign_in(env, "mikek@ucr.edu")["access_token"]
    f: Path = env["users_file"]
    f.write_text(
        USERS_YAML.replace("netid: mikek, role: read", "netid: mikek, role: staff")
    )
    os.utime(f, (time.time() + 5, time.time() + 5))
    assert tool_names(env["client"], tok) == READ_TOOLS | STAFF_TOOLS


def test_program_client_ceiling_never_grants(env: dict[str, Any]) -> None:
    tok = sign_in(
        env,
        "forsythc@ucr.edu",
        client_id="skywalker-ultra",
        redirect="http://127.0.0.1:41234/callback",
    )
    c = env["client"]
    assert tool_names(c, tok["access_token"]) == READ_TOOLS
    res = call(c, tok["access_token"], "skywalker_budgets", {})
    assert res["isError"] and "through client Ultra" in res["content"][0]["text"]


# --- tokens --------------------------------------------------------------------------


def test_no_or_bad_token_gets_401(env: dict[str, Any]) -> None:
    c = env["client"]
    r = c.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert (
        r.status_code == 401 and "resource_metadata=" in r.headers["www-authenticate"]
    )
    assert rpc(c, "swa_forged", "tools/list").status_code == 401
    assert c.get("/sse").status_code == 401
    assert c.post("/signout").status_code == 401


def test_refresh_rotates_and_is_bound_to_its_client(env: dict[str, Any]) -> None:
    tok = sign_in(env, "forsythc@ucr.edu")
    c = env["client"]
    other = register(c)
    r = c.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tok["refresh_token"],
            "client_id": other,
        },
    )
    assert r.status_code == 400
    data = {
        "grant_type": "refresh_token",
        "refresh_token": tok["refresh_token"],
        "client_id": tok["client_id"],
    }
    r1 = c.post("/token", data=data)
    assert r1.status_code == 200
    assert c.post("/token", data=data).status_code == 400


def test_authorize_never_redirects_to_unregistered_uri(env: dict[str, Any]) -> None:
    """The flaw in the old server: an unknown client_id took any redirect_uri."""
    c = env["client"]
    _, challenge = pkce()
    for cid, ru in (
        ("nope", "https://evil.example/cb"),
        (register(c), "https://evil.example/cb"),
        ("mcp_unknownclient1", "https://evil.example/cb"),
    ):
        r = c.get(
            "/authorize",
            params={
                "client_id": cid,
                "redirect_uri": ru,
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert r.status_code == 400 and "location" not in r.headers, (cid, ru)


def test_sessions_and_google_tokens_survive_a_restart(env: dict[str, Any]) -> None:
    import server
    from app import build_app

    tok = sign_in(env, "forsythc@ucr.edu")
    old: auth.AuthServer = env["server"]
    google = FakeGoogle()
    fresh = auth.AuthServer(
        old.users, SealedStore(old.store.root, load_key(env["seal_key"])), google
    )
    _project_route(env["cloud"])
    with TestClient(build_app(server.mcp, fresh), base_url=BASE) as c2:
        res = call(c2, tok["access_token"], "skywalker_projects", {"fresh": True})
        assert payload(res)["total"] == 1
    # the new process minted a Google access token from the sealed refresh token
    assert google.refreshes == ["gr-forsythc@ucr.edu"]


def test_signout_forgets_google_and_ends_sessions(env: dict[str, Any]) -> None:
    a = sign_in(env, "forsythc@ucr.edu")
    b = sign_in(env, "forsythc@ucr.edu")
    mike = sign_in(env, "mikek@ucr.edu")
    c = env["client"]
    r = c.post("/signout", headers={"Authorization": f"Bearer {a['access_token']}"})
    assert r.status_code == 200 and r.json()["tokens_ended"] >= 4
    assert not env["server"].google_tokens.has("forsythc@ucr.edu")
    assert "gr-forsythc@ucr.edu" in env["google"].revoked
    for t in (a, b):
        assert rpc(c, t["access_token"], "tools/list").status_code == 401
    assert "skywalker_overview" in tool_names(
        c, mike["access_token"]
    )  # others untouched


def test_dead_google_grant_says_sign_in_again_and_does_not_loop(
    env: dict[str, Any],
) -> None:
    tok = sign_in(env, "forsythc@ucr.edu")["access_token"]
    g: FakeGoogle = env["google"]
    srv: auth.AuthServer = env["server"]
    srv.google_tokens._hot.clear()  # force a refresh
    g.dead.add("gr-forsythc@ucr.edu")
    _project_route(env["cloud"])
    res = call(env["client"], tok, "skywalker_projects", {"fresh": True})
    assert res["isError"] and "sign in to Skywalker again" in res["content"][0]["text"]
    assert len(g.refreshes) == 1
    assert not srv.google_tokens.has("forsythc@ucr.edu")
    res = call(env["client"], tok, "skywalker_projects", {"fresh": True})
    assert res["isError"] and len(g.refreshes) == 1  # no retry storm


# --- acting as the caller --------------------------------------------------------------


def test_each_caller_uses_their_own_google_token(env: dict[str, Any]) -> None:
    c, cloud = env["client"], env["cloud"]
    _project_route(cloud)
    chuck = sign_in(env, "forsythc@ucr.edu")["access_token"]
    mike = sign_in(env, "mikek@ucr.edu")["access_token"]
    results: dict[str, Any] = {}

    def go(name: str, tok: str) -> None:
        for _ in range(5):
            results.setdefault(name, []).append(
                call(c, tok, "skywalker_projects", {"fresh": True})
            )

    threads = [
        threading.Thread(target=go, args=(n, t))
        for n, t in (("chuck", chuck), ("mike", mike))
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    toks = {call_["token"] for call_ in cloud.calls}
    assert toks == {"ga-forsythc@ucr.edu-0", "ga-mikek@ucr.edu-0"}
    # every Google call carried the server's quota project
    assert {call_["quota"] for call_ in cloud.calls} == {"quota-proj"}


def test_cache_is_per_person_and_fresh_skips_it(env: dict[str, Any]) -> None:
    c, cloud = env["client"], env["cloud"]
    _project_route(cloud)
    chuck = sign_in(env, "forsythc@ucr.edu")["access_token"]
    mike = sign_in(env, "mikek@ucr.edu")["access_token"]
    call(c, chuck, "skywalker_projects", {})
    call(c, chuck, "skywalker_projects", {})
    assert len(cloud.calls) == 1  # second answer from the cache
    call(c, mike, "skywalker_projects", {})
    assert len(cloud.calls) == 2  # never Chuck's cached answer
    assert cloud.calls[1]["token"].startswith("ga-mikek")
    call(c, chuck, "skywalker_projects", {"fresh": True})
    assert len(cloud.calls) == 3


def test_google_errors_are_mcp_errors(env: dict[str, Any]) -> None:
    env["cloud"].on(
        "GET",
        r"cloudresourcemanager.*projects:search",
        lambda p, b, t: (
            403,
            {
                "error": {
                    "code": 403,
                    "status": "PERMISSION_DENIED",
                    "message": "caller lacks permission",
                }
            },
        ),
    )
    tok = sign_in(env, "forsythc@ucr.edu")["access_token"]
    res = call(env["client"], tok, "skywalker_projects", {})
    assert (
        res["isError"]
        and "permission: caller lacks permission" in res["content"][0]["text"]
    )


def test_whoami_reports_google_token(env: dict[str, Any]) -> None:
    tok = sign_in(env, "mikek@ucr.edu")["access_token"]
    out = payload(call(env["client"], tok, "skywalker_whoami", {}))
    assert (
        out["email"] == "mikek@ucr.edu"
        and out["role"] == "read"
        and out["google_token_ok"] is True
    )
    who = (
        env["client"].get("/whoami", headers={"Authorization": f"Bearer {tok}"}).json()
    )
    assert who["google_token"] is True and auth.GCP_SCOPE in who["google_scope"]


# --- audit, limits ---------------------------------------------------------------------


def test_every_call_is_audited(env: dict[str, Any]) -> None:
    _project_route(env["cloud"])
    tok = sign_in(env, "mikek@ucr.edu")["access_token"]
    audit_lines(env)
    call(env["client"], tok, "skywalker_projects", {"query": "lab"})
    call(env["client"], tok, "skywalker_budgets", {})
    lines = [ln for ln in audit_lines(env) if ln["event"] == "tool"]
    assert [ln["decision"] for ln in lines] == ["allowed", "denied"]
    assert all(ln["email"] == "mikek@ucr.edu" for ln in lines)
    assert lines[1]["reason"] == "needs_staff"


def test_rate_limit(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(access, "CALLS_PER_MIN_CLIENT", 3)
    tok = sign_in(env, "forsythc@ucr.edu")["access_token"]
    res = [
        call(env["client"], tok, "skywalker_whoami", {})["isError"] for _ in range(5)
    ]
    assert res == [False, False, False, True, True]


def test_health_and_discovery(env: dict[str, Any]) -> None:
    c = env["client"]
    h = c.get("/health").json()
    assert h["status"] == "ok" and h["rev"] == "abc1234"
    meta = c.get("/.well-known/oauth-authorization-server").json()
    assert meta["code_challenge_methods_supported"] == ["S256"]


def test_users_file_parse(tmp_path: Path) -> None:
    f = tmp_path / "u.yaml"
    f.write_text(USERS_YAML)
    u = Users(str(f))
    assert u.lookup("michael.kennedy@ucr.edu").netid == "mikek"  # type: ignore[union-attr]
    assert u.lookup("gone@ucr.edu") is None


def test_concurrent_refresh_is_single_flight(env: dict[str, Any]) -> None:
    sign_in(env, "forsythc@ucr.edu")
    srv: auth.AuthServer = env["server"]
    srv.google_tokens._hot.clear()
    out: list[str] = []
    ts = [
        threading.Thread(
            target=lambda: out.append(
                srv.google_tokens.access_token("forsythc@ucr.edu")
            )
        )
        for _ in range(8)
    ]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(env["google"].refreshes) == 1 and len(set(out)) == 1


def test_redirect_constant_is_loopback() -> None:
    assert REDIRECT.startswith("http://127.0.0.1")


def test_tool_without_a_role_is_refused(env: dict[str, Any]) -> None:
    import server

    @server.mcp.tool()
    async def t_unregistered() -> str:
        """Registered without a role: must be refused for everyone."""
        return "should never run"

    try:
        tok = sign_in(env, "forsythc@ucr.edu")["access_token"]
        assert "t_unregistered" not in tool_names(env["client"], tok)
        res = call(env["client"], tok, "t_unregistered", {})
        assert res["isError"] and "unknown tool" in res["content"][0]["text"]
    finally:
        server.mcp._tool_manager._tools.pop("t_unregistered", None)


def test_code_needs_pkce_and_is_single_use(env: dict[str, Any]) -> None:
    import urllib.parse

    c = env["client"]
    cid = register(c)
    verifier, challenge = pkce()
    r = c.get(
        "/authorize",
        params={
            "client_id": cid,
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    google_url = r.text.split('href="', 1)[1].split('"', 1)[0].replace("&amp;", "&")
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(google_url).query)["state"][0]
    env["google"].claims = {
        "email": "forsythc@ucr.edu",
        "email_verified": True,
        "hd": "ucr.edu",
    }
    r = c.get(
        "/oauth/callback",
        params={"state": state, "code": "google-code"},
        follow_redirects=False,
    )
    code = urllib.parse.parse_qs(urllib.parse.urlsplit(r.headers["location"]).query)[
        "code"
    ][0]
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "client_id": cid,
    }
    bad = c.post("/token", data={**form, "code_verifier": "wrong-verifier"})
    assert bad.status_code == 400 and "PKCE" in bad.json()["error_description"]
    # the failed attempt used up the code
    assert c.post("/token", data={**form, "code_verifier": verifier}).status_code == 400


def test_expired_access_token_is_refused(env: dict[str, Any]) -> None:
    import auth as auth_mod

    tok = sign_in(env, "forsythc@ucr.edu")["access_token"]
    srv: auth_mod.AuthServer = env["server"]
    h = auth_mod._hash(tok)
    rec = srv.store.get("access", h)
    assert rec is not None
    # expired in memory only (the store would drop an expired record on read)
    srv._access[h] = {**rec, "expires": time.time() - 1}
    assert rpc(env["client"], tok, "tools/list").status_code == 401


def test_signout_leaves_other_people_signed_in_after_restart(
    env: dict[str, Any],
) -> None:
    """Sessions of other people survive someone else's signout, on disk too."""
    import server
    from app import build_app

    chuck = sign_in(env, "forsythc@ucr.edu")
    mike = sign_in(env, "mikek@ucr.edu")
    c = env["client"]
    assert (
        c.post(
            "/signout", headers={"Authorization": f"Bearer {chuck['access_token']}"}
        ).status_code
        == 200
    )
    old: auth.AuthServer = env["server"]
    fresh = auth.AuthServer(
        old.users, SealedStore(old.store.root, load_key(env["seal_key"])), FakeGoogle()
    )
    with TestClient(build_app(server.mcp, fresh), base_url=BASE) as c2:
        assert "skywalker_overview" in tool_names(c2, mike["access_token"])
        r = c2.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": mike["refresh_token"],
                "client_id": mike["client_id"],
            },
        )
        assert r.status_code == 200
    assert env["server"].google_tokens.has("mikek@ucr.edu")


def test_google_request_has_no_incremental_auth(env: dict[str, Any]) -> None:
    """The OAuth client is shared; incremental auth would pull in Gmail/Drive scopes."""
    import urllib.parse

    c = env["client"]
    _, challenge = pkce()
    r = c.get(
        "/authorize",
        params={
            "client_id": register(c),
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    url = r.text.split('href="', 1)[1].split('"', 1)[0].replace("&amp;", "&")
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert "include_granted_scopes" not in q
    assert q["scope"] == [f"openid email {auth.GCP_SCOPE}"]


def test_refresh_asks_only_for_the_cloud_scope(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: dict[str, Any] = {}

    class Resp:
        status_code = 200

        def json(self) -> dict[str, Any]:
            return {"access_token": "narrow", "expires_in": 3600}

    def fake_post(url: str, data: dict[str, Any], timeout: float) -> Resp:
        sent.update(data)
        return Resp()

    monkeypatch.setattr(auth.httpx, "post", fake_post)
    real = auth.Google("cid", "secret")
    assert real.refresh("rt")["access_token"] == "narrow"
    assert sent["scope"] == auth.GCP_SCOPE


def test_broad_sign_in_token_is_not_used(env: dict[str, Any]) -> None:
    """A sign-in access token carrying extra scopes is dropped; a narrowed one is minted."""
    g: FakeGoogle = env["google"]
    g.scope = (
        f"openid email {auth.GCP_SCOPE} https://www.googleapis.com/auth/gmail.modify"
    )
    sign_in(env, "forsythc@ucr.edu")
    tok = env["server"].google_tokens.access_token("forsythc@ucr.edu")
    assert tok != "ga-forsythc@ucr.edu-0" and g.refreshes == ["gr-forsythc@ucr.edu"]
