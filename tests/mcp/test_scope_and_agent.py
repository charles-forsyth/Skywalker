"""Project scope (who may ask about which project), focus, the Gemini Enterprise
confidential client, and the A2A agent end to end with a fake model."""

from __future__ import annotations

import base64
import copy
import json
import urllib.parse
from collections.abc import Iterator
from typing import Any

import pytest
import scope
from conftest import BASE, audit_lines, call, payload, pkce, sign_in
from starlette.testclient import TestClient
from users import UsersFileError, parse, project_allowed

GE = "skywalker-gemini-enterprise"
GE_REDIRECT = "https://vertexaisearch.cloud.google.com/static/oauth/oauth.html"


def _bq_ok(cloud: Any) -> list[dict[str, Any]]:
    """A billing export that answers any query; returns the list of queries seen."""
    seen: list[dict[str, Any]] = []

    def q(p: Any, body: Any, t: Any) -> Any:
        seen.append(body)
        return (
            200,
            {
                "jobComplete": True,
                "schema": {
                    "fields": [
                        {"name": "k", "type": "STRING"},
                        {"name": "gross", "type": "FLOAT"},
                        {"name": "credits", "type": "FLOAT"},
                        {"name": "net", "type": "FLOAT"},
                    ]
                },
                "rows": [{"f": [{"v": "Compute"}, {"v": "5"}, {"v": "0"}, {"v": "5"}]}],
                "totalBytesProcessed": "10",
                "cacheHit": False,
            },
        )

    cloud.on("POST", r"bigquery\.googleapis\.com/.*/queries", q)
    return seen


def _cfg(monkeypatch: pytest.MonkeyPatch) -> None:
    import server

    from skywalker.intel import IntelConfig

    monkeypatch.setattr(
        server,
        "CONFIG",
        IntelConfig(billing_table="p.d.t", job_project="job-proj"),
    )


def _projects_of(seen: list[dict[str, Any]]) -> list[str]:
    out = []
    for body in seen:
        for prm in body.get("queryParameters", []):
            if prm["name"] == "project":
                out.append(prm["parameterValue"]["value"])
    return out


# --- users.yaml -------------------------------------------------------------------


def test_projects_field_is_validated() -> None:
    base = "domain: ucr.edu\nusers:\n  - {email: a@ucr.edu, netid: a, role: read, projects: %s}\n"
    assert parse(base % "[ok-project-1, 'lab-*']").users[0].projects == (
        "ok-project-1",
        "lab-*",
    )
    for bad in ("[Bad_Project]", "['*']", "[x]", "notalist", "['a b']"):
        with pytest.raises(UsersFileError):
            parse(base % bad)


def test_project_patterns() -> None:
    pats = ("lab-one-proj", "lab-two-*")
    assert project_allowed(pats, "lab-one-proj")
    assert project_allowed(pats, "lab-two-anything")
    assert not project_allowed(pats, "lab-one-proj2")
    assert not project_allowed(pats, "lab-three")
    assert not project_allowed((), "lab-one-proj")


# --- read users: only their projects -----------------------------------------------


def test_read_user_refused_outside_their_projects_before_google(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _cfg(monkeypatch)
    seen = _bq_ok(env["cloud"])
    c = env["client"]
    mike = sign_in(env, "mikek@ucr.edu")["access_token"]
    for tool in ("skywalker_spend", "skywalker_overview", "skywalker_access"):
        res = call(c, mike, tool, {"project_id": "someone-elses-proj"})
        assert res["isError"], tool
        assert "not one of your Skywalker projects" in res["content"][0]["text"]
    # nothing reached Google for the refused calls
    assert env["cloud"].calls == [] and seen == []
    # their own exact project and a prefix match are fine
    payload(call(c, mike, "skywalker_spend", {"project_id": "lab-one-proj"}))
    payload(call(c, mike, "skywalker_spend", {"project_id": "lab-two-gpu"}))
    assert _projects_of(seen) == ["lab-one-proj", "lab-two-gpu"]


def test_read_user_defaults_to_their_first_project(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _cfg(monkeypatch)
    seen = _bq_ok(env["cloud"])
    mike = sign_in(env, "mikek@ucr.edu")["access_token"]
    out = payload(call(env["client"], mike, "skywalker_spend", {}))
    assert out["project_id"] == "lab-one-proj"
    assert _projects_of(seen) == ["lab-one-proj"]


def test_read_user_with_no_projects_gets_a_clear_answer(env: dict[str, Any]) -> None:
    tok = sign_in(env, "nolab@ucr.edu")["access_token"]
    res = call(env["client"], tok, "skywalker_overview", {})
    assert res["isError"]
    assert "no Google Cloud project is assigned" in res["content"][0]["text"]
    res = call(env["client"], tok, "skywalker_overview", {"project_id": "any-proj-1"})
    assert res["isError"] and "yours: none" in res["content"][0]["text"]
    assert env["cloud"].calls == []


def test_read_user_project_list_is_filtered(env: dict[str, Any]) -> None:
    env["cloud"].on(
        "GET",
        r"projects:search",
        lambda p, b, t: (
            200,
            {
                "projects": [
                    {"projectId": pid, "name": f"projects/{i}", "parent": "folders/9"}
                    for i, pid in enumerate(
                        ["lab-one-proj", "lab-two-gpu", "other-lab-proj", "home-proj"]
                    )
                ]
            },
        ),
    )
    mike = sign_in(env, "mikek@ucr.edu")["access_token"]
    out = payload(call(env["client"], mike, "skywalker_projects", {}))
    assert [p["project_id"] for p in out["projects"]] == ["lab-one-proj", "lab-two-gpu"]
    chuck = sign_in(env, "forsythc@ucr.edu")["access_token"]
    out = payload(call(env["client"], chuck, "skywalker_projects", {"fresh": True}))
    assert out["total"] == 4


def test_read_user_cannot_focus_elsewhere_or_on_all(env: dict[str, Any]) -> None:
    c = env["client"]
    mike = sign_in(env, "mikek@ucr.edu")["access_token"]
    for bad in ("someone-elses-proj", "all"):
        res = call(c, mike, "skywalker_focus", {"project_id": bad})
        assert res["isError"], bad
        assert env["server"].store.get("focus", "mikek@ucr.edu") is None, bad
    out = payload(call(c, mike, "skywalker_focus", {"project_id": "lab-two-gpu"}))
    assert out["focus"] == "lab-two-gpu"
    # a saved focus that later leaves their list stops counting
    env["users_file"].write_text(
        env["users_file"]
        .read_text()
        .replace('projects: [lab-one-proj, "lab-two-*"]', "projects: [lab-one-proj]")
    )
    env["server"].users.recheck = 0
    out = payload(call(c, mike, "skywalker_focus", {}))
    assert out["focus"] == "lab-one-proj"


# --- staff/admin: any project, focus, 'all' ----------------------------------------------


def test_admin_any_project_focus_and_all(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _cfg(monkeypatch)
    seen = _bq_ok(env["cloud"])
    c = env["client"]
    chuck = sign_in(env, "forsythc@ucr.edu")["access_token"]
    # default focus is the first listed project
    assert payload(call(c, chuck, "skywalker_spend", {}))["project_id"] == "home-proj"
    # any project Google lets him see
    payload(call(c, chuck, "skywalker_spend", {"project_id": "someone-elses-proj"}))
    # switch focus; it follows him to another client
    payload(call(c, chuck, "skywalker_focus", {"project_id": "lab-one-proj"}))
    other_client = sign_in(env, "forsythc@ucr.edu")["access_token"]
    assert (
        payload(call(c, other_client, "skywalker_spend", {}))["project_id"]
        == "lab-one-proj"
    )
    assert _projects_of(seen) == ["home-proj", "someone-elses-proj", "lab-one-proj"]
    # 'all': per-project tools ask for a project, overview becomes the fleet view
    payload(call(c, chuck, "skywalker_focus", {"project_id": "all"}))
    res = call(c, chuck, "skywalker_spend", {})
    assert res["isError"] and "your focus is 'all'" in res["content"][0]["text"]
    who = payload(call(c, chuck, "skywalker_whoami", {}))
    assert who["focus"] == "all"
    out = payload(call(c, chuck, "skywalker_focus", {"reset": True}))
    assert out["focus"] == "home-proj" and out["default"] == "home-proj"


def test_overview_with_focus_all_is_the_fleet_view(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    import server

    calls: list[str] = []
    monkeypatch.setattr(
        server.overview,
        "fleet",
        lambda g, cfg, limit: calls.append("fleet") or {"ok": 1},
    )
    monkeypatch.setattr(
        server.overview,
        "overview",
        lambda g, cfg, p, deep: calls.append(p) or {"ok": 2},
    )
    c = env["client"]
    chuck = sign_in(env, "forsythc@ucr.edu")["access_token"]
    payload(call(c, chuck, "skywalker_focus", {"project_id": "all"}))
    assert payload(call(c, chuck, "skywalker_overview", {})) == {"ok": 1}
    assert payload(
        call(c, chuck, "skywalker_overview", {"project_id": "x-proj-1"})
    ) == {"ok": 2}
    assert calls == ["fleet", "x-proj-1"]


def test_staff_without_projects_must_name_one(env: dict[str, Any]) -> None:
    tok = sign_in(env, "staffer@ucr.edu")["access_token"]
    res = call(env["client"], tok, "skywalker_compute", {})
    assert res["isError"] and "which project?" in res["content"][0]["text"]


def test_focus_is_sealed_and_per_person(env: dict[str, Any]) -> None:
    c = env["client"]
    chuck = sign_in(env, "forsythc@ucr.edu")["access_token"]
    mike = sign_in(env, "mikek@ucr.edu")["access_token"]
    payload(call(c, chuck, "skywalker_focus", {"project_id": "secret-lab-proj"}))
    assert payload(call(c, mike, "skywalker_focus", {}))["focus"] == "lab-one-proj"
    for f in (env["tmp"] / "data").rglob("*"):
        if f.is_file():
            assert b"secret-lab-proj" not in f.read_bytes()


# --- Gemini Enterprise confidential client --------------------------------------------


def _ge_code(env: dict[str, Any], with_pkce: bool) -> tuple[str, str]:
    """Run GE's sign-in up to the code; returns (code, verifier)."""
    c: TestClient = env["client"]
    verifier, challenge = pkce()
    params = {
        "client_id": GE,
        "redirect_uri": GE_REDIRECT,
        "response_type": "code",
        "state": "st8",
        "scope": "mcp",
    }
    if with_pkce:
        params |= {"code_challenge": challenge, "code_challenge_method": "S256"}
    r = c.get("/authorize", params=params, follow_redirects=False)
    assert r.status_code in (200, 302), r.text
    loc = (
        r.headers["location"]
        if r.status_code == 302
        else r.text.split('href="', 1)[1].split('"', 1)[0].replace("&amp;", "&")
    )
    g = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
    env["google"].claims = {
        "email": "forsythc@ucr.edu",
        "email_verified": True,
        "hd": "ucr.edu",
    }
    r = c.get(
        "/oauth/callback",
        params={"state": g["state"][0], "code": "google-code"},
        follow_redirects=False,
    )
    assert r.status_code == 302, r.text
    back = urllib.parse.parse_qs(urllib.parse.urlsplit(r.headers["location"]).query)
    assert r.headers["location"].startswith(GE_REDIRECT)
    return back["code"][0], verifier


def test_confidential_client_needs_its_secret(env: dict[str, Any]) -> None:
    c = env["client"]
    code, _ = _ge_code(env, with_pkce=False)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": GE_REDIRECT,
        "client_id": GE,
        "client_secret": "wrong",
    }
    r = c.post("/token", data=form)
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"
    # the code was consumed by the failed attempt: single use holds
    code, _ = _ge_code(env, with_pkce=False)
    basic = base64.b64encode(f"{GE}:ge-secret".encode()).decode()
    r = c.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": GE_REDIRECT,
        },
        headers={"Authorization": f"Basic {basic}"},
    )
    assert r.status_code == 200, r.text
    tok = r.json()
    # refresh also needs the secret
    r = c.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tok["refresh_token"],
            "client_id": GE,
        },
    )
    assert r.status_code == 401
    r = c.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tok["refresh_token"],
            "client_id": GE,
            "client_secret": "ge-secret",
        },
    )
    assert r.status_code == 200
    who = c.get(
        "/whoami", headers={"Authorization": f"Bearer {r.json()['access_token']}"}
    )
    assert who.json()["client_id"] == GE and who.json()["role"] == "admin"


def test_confidential_client_pkce_still_checked_when_sent(env: dict[str, Any]) -> None:
    code, _verifier = _ge_code(env, with_pkce=True)
    r = env["client"].post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": GE_REDIRECT,
            "client_id": GE,
            "client_secret": "ge-secret",
            "code_verifier": "not-the-verifier",
        },
    )
    assert r.status_code == 400 and "PKCE" in r.json()["error_description"]


def test_public_clients_still_need_pkce(env: dict[str, Any]) -> None:
    c = env["client"]
    r = c.post("/register", json={"redirect_uris": ["http://127.0.0.1:9/cb"]})
    cid = r.json()["client_id"]
    r = c.get(
        "/authorize",
        params={
            "client_id": cid,
            "redirect_uri": "http://127.0.0.1:9/cb",
            "response_type": "code",
            "state": "s",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302 and "PKCE" in urllib.parse.unquote(
        r.headers["location"]
    )


def test_secret_must_be_sha256_in_users_file() -> None:
    y = (
        "domain: ucr.edu\nclients:\n  - {id: ge-client, max_role: read, "
        "client_secret_sha256: plaintext, redirect_uris: ['https://x.example/cb']}\n"
    )
    with pytest.raises(UsersFileError):
        parse(y)


# --- A2A agent -----------------------------------------------------------------------


class FakeModel:
    """Scripted Gemini: each turn returns the next list of parts."""

    def __init__(self, script: list[list[dict[str, Any]]]) -> None:
        self.script = list(script)
        self.seen: list[dict[str, Any]] = []

    async def generate(
        self, system: str, contents: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        self.seen.append(
            {
                "system": system,
                "contents": copy.deepcopy(contents),
                "tools": [t["name"] for t in tools],
            }
        )
        parts = self.script.pop(0) if self.script else [{"text": "done"}]
        return parts, {"totalTokenCount": 10}


@pytest.fixture
def a2a(env: dict[str, Any]) -> Iterator[dict[str, Any]]:
    import agent
    import server
    from app import build_app

    model = FakeModel([])
    env["client"].__exit__(None, None, None)
    client = TestClient(
        build_app(
            server.mcp,
            env["server"],
            quota_project="quota-proj",
            agent_routes=agent.build_routes(server.mcp, BASE, model),
        ),
        base_url=BASE,
    )
    client.__enter__()
    env["client"] = client
    env["model"] = model
    yield env
    client.__exit__(None, None, None)


def _send(c: TestClient, tok: str | None, text: str, ctx: str = "ctx-1") -> Any:
    headers = {"Content-Type": "application/json"}
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    return c.post(
        "/a2a/",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "messageId": "m-" + text[:8],
                    "contextId": ctx,
                    "parts": [{"kind": "text", "text": text}],
                }
            },
        },
    )


def _answer(r: Any) -> str:
    assert r.status_code == 200, r.text
    res = r.json()["result"]
    assert res["status"]["state"] == "completed", res
    return "".join(p["text"] for a in res["artifacts"] for p in a["parts"])


def test_agent_card_is_public_and_points_at_sign_in(a2a: dict[str, Any]) -> None:
    c = a2a["client"]
    for path in ("/a2a/.well-known/agent-card.json", "/.well-known/agent-card.json"):
        card = c.get(path).json()
        assert card["url"] == f"{BASE}/a2a/" and card["protocolVersion"] == "0.3.0"
        flow = card["securitySchemes"]["skywalker"]["flows"]["authorizationCode"]
        assert flow["authorizationUrl"] == f"{BASE}/authorize"
        assert flow["tokenUrl"] == f"{BASE}/token"
        assert card["iconUrl"].startswith("data:image/svg+xml;base64,")


def test_agent_needs_a_skywalker_token(a2a: dict[str, Any]) -> None:
    c = a2a["client"]
    assert _send(c, None, "hi").status_code == 401
    assert _send(c, "swa_not-a-token", "hi").status_code == 401
    assert a2a["model"].seen == []


def test_agent_tools_run_as_the_caller_with_scope_and_audit(
    a2a: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _cfg(monkeypatch)
    seen = _bq_ok(a2a["cloud"])
    c, model = a2a["client"], a2a["model"]
    mike = sign_in(a2a, "mikek@ucr.edu")["access_token"]
    model.script = [
        [
            {"functionCall": {"name": "skywalker_spend", "args": {}, "id": "1"}},
            {
                "functionCall": {
                    "name": "skywalker_spend",
                    "args": {"project_id": "someone-elses-proj"},
                    "id": "2",
                }
            },
            {"functionCall": {"name": "skywalker_fleet", "args": {}, "id": "3"}},
        ],
        [{"text": "Your lab spent $5 this month."}],
    ]
    audit_lines(a2a)
    assert _answer(_send(c, mike, "How much did we spend?")) == (
        "Your lab spent $5 this month."
    )
    # the model saw only Mike's tools, and his scope in the instructions
    first = model.seen[0]
    assert (
        "skywalker_fleet" not in first["tools"] and "skywalker_spend" in first["tools"]
    )
    assert "lab-one-proj" in first["system"] and "mikek@ucr.edu" in first["system"]
    # the tool results it got back: one answer, two refusals
    results = [
        p["functionResponse"]["response"]
        for p in model.seen[1]["contents"][-1]["parts"]
    ]
    assert "result" in results[0]
    assert "not one of your Skywalker projects" in results[1]["error"]
    assert "needs the 'staff' role" in results[2]["error"]
    # Google was asked once, about Mike's project, with Mike's own token
    assert _projects_of(seen) == ["lab-one-proj"]
    assert {x["token"] for x in a2a["cloud"].calls} == {"ga-mikek@ucr.edu-0"}
    lines = audit_lines(a2a)
    tools = [ln for ln in lines if ln["event"] == "tool"]
    # the three calls run in parallel, so compare without order
    assert sorted(ln["decision"] for ln in tools) == ["allowed", "denied", "error"]
    assert all(
        ln["channel"] == "a2a" and ln["email"] == "mikek@ucr.edu" for ln in tools
    )
    done = [ln for ln in lines if ln["event"] == "a2a"]
    assert done and done[0]["decision"] == "allowed" and done[0]["tokens"] == 20


def test_agent_remembers_the_conversation_per_person(a2a: dict[str, Any]) -> None:
    c, model = a2a["client"], a2a["model"]
    chuck = sign_in(a2a, "forsythc@ucr.edu")["access_token"]
    mike = sign_in(a2a, "mikek@ucr.edu")["access_token"]
    model.script = [
        [{"text": "first answer"}],
        [{"text": "second"}],
        [{"text": "mike"}],
    ]
    _answer(_send(c, chuck, "question one"))
    _answer(_send(c, chuck, "question two"))
    texts = [p["text"] for t in model.seen[1]["contents"] for p in t["parts"]]
    assert texts == ["question one", "first answer", "question two"]
    # same context id from another person starts fresh
    _answer(_send(c, mike, "question three"))
    assert len(model.seen[2]["contents"]) == 1


def test_agent_tasks_are_private(a2a: dict[str, Any]) -> None:
    c, model = a2a["client"], a2a["model"]
    chuck = sign_in(a2a, "forsythc@ucr.edu")["access_token"]
    mike = sign_in(a2a, "mikek@ucr.edu")["access_token"]
    model.script = [[{"text": "private answer"}]]
    task_id = _send(c, chuck, "hello").json()["result"]["id"]

    def get(tok: str) -> Any:
        return c.post(
            "/a2a/",
            headers={"Authorization": f"Bearer {tok}"},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tasks/get",
                "params": {"id": task_id},
            },
        ).json()

    assert get(chuck)["result"]["id"] == task_id
    assert "error" in get(mike) and "private answer" not in json.dumps(get(mike))


def test_agent_rate_limit(a2a: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    import agent

    monkeypatch.setattr(agent, "MESSAGES_PER_MIN", 2)
    c = a2a["client"]
    tok = sign_in(a2a, "mikek@ucr.edu")["access_token"]
    states = [
        _send(c, tok, f"q{i}").json()["result"]["status"]["state"] for i in range(3)
    ]
    assert states == ["completed", "completed", "failed"]


def test_agent_stops_after_max_rounds(a2a: dict[str, Any]) -> None:
    import agent

    c, model = a2a["client"], a2a["model"]
    tok = sign_in(a2a, "forsythc@ucr.edu")["access_token"]
    loop = [{"functionCall": {"name": "skywalker_whoami", "args": {}}}]
    model.script = [loop] * (agent.MAX_ROUNDS + 2)
    assert "more steps" in _answer(_send(c, tok, "loop forever"))
    assert len(model.seen) == agent.MAX_ROUNDS


def test_removed_user_loses_the_agent_too(a2a: dict[str, Any]) -> None:
    c = a2a["client"]
    tok = sign_in(a2a, "mikek@ucr.edu")["access_token"]
    a2a["users_file"].write_text(
        a2a["users_file"]
        .read_text()
        .replace("role: read, aliases", "role: read, disabled: true, aliases")
    )
    a2a["server"].users.recheck = 0
    assert _send(c, tok, "still there?").status_code == 403


def test_read_user_stored_all_does_not_count(env: dict[str, Any]) -> None:
    # e.g. a staff member focused on 'all' and was later lowered to read
    env["server"].store.put("focus", "mikek@ucr.edu", {"project": "all"})
    mike = sign_in(env, "mikek@ucr.edu")["access_token"]
    out = payload(call(env["client"], mike, "skywalker_focus", {}))
    assert out["focus"] == "lab-one-proj"
    res = call(env["client"], mike, "skywalker_overview", {"project_id": "all"})
    assert res["isError"] and "'all' is for staff" in res["content"][0]["text"]


def test_scope_module_has_no_google_calls() -> None:
    # scope decisions happen before any Google call: the module never imports intel
    import inspect

    src = inspect.getsource(scope)
    assert "skywalker.intel" not in src and "requests" not in src
