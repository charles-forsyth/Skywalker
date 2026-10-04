"""skywalker.intel: read-only guard, error mapping, and each function on a fake cloud."""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from skywalker.intel import (
    Gcp,
    GcpError,
    IntelConfig,
    billing,
    iam,
    inventory,
    ops,
    overview,
    recommend,
    security,
)
from skywalker.intel.gcp import check_read_only
from skywalker.intel.util import period

P = "lab-one-proj"
CFG = IntelConfig(
    billing_table="bill-proj.dataset.export_table",
    billing_account="000000-AAAAAA-BBBBBB",
    job_project="job-proj",
    fleet_scopes=("folders/123",),
)


def make(cloud: Any) -> Gcp:
    return Gcp("tok-a", quota_project="quota-proj", session_factory=cloud.session)


# --- the read-only guard ---------------------------------------------------------------


@pytest.mark.parametrize(
    "method,url,body",
    [
        (
            "DELETE",
            "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/i",
            None,
        ),
        (
            "POST",
            "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/i/stop",
            None,
        ),
        (
            "PATCH",
            "https://billingbudgets.googleapis.com/v1/billingAccounts/x/budgets/y",
            {},
        ),
        (
            "POST",
            "https://cloudresourcemanager.googleapis.com/v1/projects/p:setIamPolicy",
            {},
        ),
        (
            "POST",
            "https://serviceusage.googleapis.com/v1/projects/p/services/x:disable",
            {},
        ),
        ("PUT", "https://storage.googleapis.com/storage/v1/b/x", {}),
        (
            "POST",
            "https://bigquery.googleapis.com/bigquery/v2/projects/p/queries",
            {"query": "DELETE FROM t WHERE true"},
        ),
        (
            "POST",
            "https://bigquery.googleapis.com/bigquery/v2/projects/p/queries",
            {"query": "SELECT 1; DROP TABLE t"},
        ),
        (
            "POST",
            "https://bigquery.googleapis.com/bigquery/v2/projects/p/queries",
            {"query": "CREATE TABLE x AS SELECT 1"},
        ),
        ("POST", "https://bigquery.googleapis.com/bigquery/v2/projects/p/jobs", {}),
        ("POST", "https://logging.googleapis.com/v2/entries:write", {}),
        (
            "POST",
            "https://cloudresourcemanager.googleapis.com/v1/projects/p:getIamPolicy/x",
            {},
        ),
    ],
)
def test_writes_are_refused_before_any_request(
    method: str, url: str, body: Any, cloud: Any
) -> None:
    with pytest.raises(GcpError) as e:
        check_read_only(method, url, body)
    assert e.value.kind == "refused"
    g = make(cloud)
    with pytest.raises(GcpError):
        g.request(method, url, body=body)
    assert cloud.calls == []  # nothing left the process


@pytest.mark.parametrize(
    "method,url,body",
    [
        (
            "GET",
            "https://compute.googleapis.com/compute/v1/projects/p/aggregated/instances",
            None,
        ),
        (
            "POST",
            "https://cloudresourcemanager.googleapis.com/v1/projects/p-1:getIamPolicy",
            {},
        ),
        ("POST", "https://logging.googleapis.com/v2/entries:list", {}),
        (
            "POST",
            "https://bigquery.googleapis.com/bigquery/v2/projects/job-proj/queries",
            {"query": "SELECT SUM(cost) FROM `a.b.c` WHERE x = @p"},
        ),
        (
            "POST",
            "https://bigquery.googleapis.com/bigquery/v2/projects/job-proj/queries",
            {"query": "WITH a AS (SELECT 1) SELECT * FROM a"},
        ),
    ],
)
def test_reads_are_allowed(method: str, url: str, body: Any) -> None:
    check_read_only(method, url, body)


def test_every_intel_url_is_a_known_read(cloud: Any) -> None:
    """Grep guard: no intel module builds a write verb or a non-allowlisted POST."""
    import pathlib
    import re

    import skywalker.intel as pkg

    src = pathlib.Path(pkg.__file__).parent
    for f in src.glob("*.py"):
        text = f.read_text()
        assert not re.search(r"\.request\(\s*\"(DELETE|PUT|PATCH)\"", text), f
        for m in re.finditer(r"gcp\.post\(\s*f?\"([^\"]+)\"", text):
            assert "getIamPolicy" in m.group(1) or "entries:list" in m.group(1), (
                f,
                m.group(1),
            )


# --- error mapping and retries ----------------------------------------------------------


def test_error_kinds(cloud: Any) -> None:
    g = make(cloud)
    cases = {
        "/a": (
            403,
            {
                "error": {
                    "code": 403,
                    "status": "PERMISSION_DENIED",
                    "message": "API has not been used in project",
                }
            },
        ),
        "/b": (
            403,
            {"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "nope"}},
        ),
        "/c": (404, {"error": {"code": 404, "message": "gone"}}),
        "/d": (400, {"error": {"code": 400, "message": "bad"}}),
        "/e": (401, {"error": {"code": 401, "message": "expired"}}),
    }
    for path, resp in cases.items():
        cloud.on("GET", path + "$", lambda p, b, t, r=resp: r)
    kinds = {}
    for path in cases:
        with pytest.raises(GcpError) as e:
            g.get("https://x.googleapis.com" + path)
        kinds[path] = e.value.kind
    assert kinds == {
        "/a": "api_disabled",
        "/b": "permission",
        "/c": "not_found",
        "/d": "invalid",
        "/e": "auth",
    }


def test_retries_5xx_then_succeeds(cloud: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import skywalker.intel.gcp as gm

    monkeypatch.setattr(gm.time, "sleep", lambda s: None)
    n = {"i": 0}

    def flaky(p: Any, b: Any, t: Any) -> Any:
        n["i"] += 1
        return (503, {"error": {"message": "busy"}}) if n["i"] < 3 else (200, {"ok": 1})

    cloud.on("GET", r"/flaky$", flaky)
    assert make(cloud).get("https://x.googleapis.com/flaky") == {"ok": 1}


def test_quota_project_dropped_when_caller_may_not_use_it(cloud: Any) -> None:
    def h(p: Any, b: Any, t: Any) -> Any:
        last = cloud.calls[-1]
        if last["quota"]:
            return 403, {
                "error": {
                    "code": 403,
                    "status": "PERMISSION_DENIED",
                    "message": "USER_PROJECT_DENIED",
                }
            }
        return 200, {"ok": True}

    cloud.on("GET", r"/q$", h)
    assert make(cloud).get("https://x.googleapis.com/q") == {"ok": True}
    assert [c["quota"] for c in cloud.calls] == ["quota-proj", None]


def test_paging(cloud: Any) -> None:
    def pages(p: Any, b: Any, t: Any) -> Any:
        if p.get("pageToken") == "2":
            return 200, {"items": [3]}
        return 200, {"items": [1, 2], "nextPageToken": "2"}

    cloud.on("GET", r"/list$", pages)
    assert list(make(cloud).paged("https://x.googleapis.com/list", {}, "items")) == [
        1,
        2,
        3,
    ]
    assert list(
        make(cloud).paged("https://x.googleapis.com/list", {}, "items", limit=2)
    ) == [1, 2]


def test_invalid_project_id_never_reaches_google(cloud: Any) -> None:
    for bad in ("../etc", "Proj With Space", "a", "x" * 40, "p/q"):
        with pytest.raises(GcpError) as e:
            inventory.compute(make(cloud), bad)
        assert e.value.kind == "invalid"
    assert cloud.calls == []


# --- billing ---------------------------------------------------------------------------


def _bq(rows: list[list[Any]], fields: list[tuple[str, str]]) -> dict[str, Any]:
    return {
        "jobComplete": True,
        "jobReference": {"jobId": "j1", "location": "US"},
        "schema": {"fields": [{"name": n, "type": t} for n, t in fields]},
        "rows": [{"f": [{"v": v} for v in r]} for r in rows],
        "totalBytesProcessed": "1000",
    }


def test_spend_uses_parameters_partition_filter_and_byte_cap(cloud: Any) -> None:
    seen: dict[str, Any] = {}

    def q(p: Any, body: Any, t: Any) -> Any:
        seen.update(body)
        return 200, _bq(
            [["Compute Engine", "10.5", "-10.5", "0"], ["Gemini API", "2", "-1", "1"]],
            [
                ("k", "STRING"),
                ("gross", "FLOAT"),
                ("credits", "FLOAT"),
                ("net", "FLOAT"),
            ],
        )

    cloud.on("POST", r"bigquery.*/projects/job-proj/queries$", q)
    out = billing.spend(make(cloud), CFG, P, "service")
    assert out["total"] == {"gross": 12.5, "credits": -11.5, "net": 1.0}
    assert out["items"][0] == {
        "service": "Compute Engine",
        "gross": 10.5,
        "credits": -10.5,
        "net": 0.0,
    }
    sql = seen["query"]
    assert (
        "_PARTITIONTIME BETWEEN @pstart AND @pend" in sql
        and "project.id = @project" in sql
    )
    assert P not in sql  # the id is a parameter, never spliced into SQL
    assert {
        "name": "project",
        "parameterType": {"type": "STRING"},
        "parameterValue": {"value": P},
    } in seen["queryParameters"]
    assert int(seen["maximumBytesBilled"]) == CFG.max_bytes


def test_spend_rejects_unknown_grouping(cloud: Any) -> None:
    with pytest.raises(GcpError):
        billing.spend(make(cloud), CFG, P, "1; DROP TABLE x")
    assert cloud.calls == []


def test_spend_needs_configuration(cloud: Any) -> None:
    with pytest.raises(GcpError) as e:
        billing.spend(make(cloud), IntelConfig(), P)
    assert "not configured" in str(e.value)


def test_period_month_and_days() -> None:
    s, e, label = period(month="2026-02")
    assert label == "2026-02" and s.isoformat().startswith("2026-02-01T08:00")
    s, e, label = period(days=7)
    assert round((e - s).total_seconds() / 86400) == 7
    with pytest.raises(GcpError):
        period(month="26-2")


def test_budgets_vs_spend(cloud: Any) -> None:
    cloud.on(
        "GET",
        r"cloudresourcemanager.*projects:search",
        {
            "projects": [
                {"projectId": P, "name": "projects/111"},
                {"projectId": "other-proj", "name": "projects/222"},
            ]
        },
    )
    cloud.on(
        "GET",
        r"billingbudgets.*/budgets$",
        {
            "budgets": [
                {
                    "name": "billingAccounts/x/budgets/b1",
                    "displayName": "lab-one-budget",
                    "budgetFilter": {
                        "projects": ["projects/111"],
                        "creditTypesTreatment": "EXCLUDE_ALL_CREDITS",
                        "calendarPeriod": "MONTH",
                    },
                    "amount": {"specifiedAmount": {"units": "1000"}},
                    "thresholdRules": [
                        {"thresholdPercent": 0.5},
                        {"thresholdPercent": 1},
                    ],
                    "notificationsRule": {
                        "pubsubTopic": "projects/lab-one-proj/topics/t"
                    },
                },
            ]
        },
    )
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    cloud.on(
        "POST",
        r"bigquery",
        lambda p, b, t: (
            200,
            _bq(
                [
                    [P, "111", today, "1200", "-1200"],
                    ["other-proj", "222", today, "50", "-50"],
                ],
                [
                    ("project", "STRING"),
                    ("number", "STRING"),
                    ("day", "DATE"),
                    ("gross", "FLOAT"),
                    ("credits", "FLOAT"),
                ],
            ),
        ),
    )
    out = billing.budgets(make(cloud), CFG)
    b = out["budgets"][0]
    assert b["projects"] == [P] and b["pct"] == 120.0 and b["spend_basis"] == "gross"
    assert out["summary"]["over_100pct"] == 1
    assert out["unbudgeted"][0]["project_id"] == "other-proj"


def test_trend_separates_account_level_charges(cloud: Any) -> None:
    now = dt.datetime.now(dt.timezone.utc).date()
    d_new, d_old = (
        (now - dt.timedelta(days=1)).isoformat(),
        (now - dt.timedelta(days=10)).isoformat(),
    )
    cloud.on(
        "POST",
        r"bigquery",
        lambda p, b, t: (
            200,
            _bq(
                [
                    [P, "1", d_new, "300", "0"],
                    [P, "1", d_old, "100", "0"],
                    [None, None, d_new, "9999", "0"],
                ],
                [
                    ("project", "STRING"),
                    ("number", "STRING"),
                    ("day", "DATE"),
                    ("gross", "FLOAT"),
                    ("credits", "FLOAT"),
                ],
            ),
        ),
    )
    out = billing.trend(make(cloud), CFG)
    assert out["rising"][0]["project_id"] == P and out["rising"][0]["change"] == 200
    assert out["account_level"]["gross_last7"] == 9999
    assert all(r["project_id"] for r in out["rising"])


# --- inventory, iam, security, recommender, ops ------------------------------------------


def test_compute_summary(cloud: Any) -> None:
    cloud.on(
        "GET",
        r"aggregated/instances",
        {
            "items": {
                "zones/us-central1-a": {
                    "instances": [
                        {
                            "name": "gpu1",
                            "status": "RUNNING",
                            "machineType": ".../a2-highgpu-1g",
                            "networkInterfaces": [
                                {"accessConfigs": [{"natIP": "1.2.3.4"}]}
                            ],
                        },
                        {
                            "name": "old",
                            "status": "TERMINATED",
                            "machineType": ".../e2-medium",
                            "lastStopTimestamp": "2026-01-01T00:00:00Z",
                        },
                    ]
                }
            }
        },
    )
    cloud.on(
        "GET",
        r"aggregated/disks",
        {
            "items": {
                "zones/us-central1-a": {
                    "disks": [
                        {"name": "d1", "sizeGb": "500", "users": []},
                        {"name": "d2", "sizeGb": "10", "users": ["x/gpu1"]},
                    ]
                }
            }
        },
    )
    cloud.on(
        "GET",
        r"aggregated/addresses",
        {
            "items": {
                "regions/us-central1": {
                    "addresses": [
                        {"name": "ip1", "status": "RESERVED", "addressType": "EXTERNAL"}
                    ]
                }
            }
        },
    )
    cloud.on(
        "GET",
        r"global/snapshots",
        {"items": [{"name": "s", "storageBytes": str(2 * 1024**3)}]},
    )
    cloud.on("GET", r"global/images", {"items": []})
    s = inventory.compute(make(cloud), P)["summary"]
    assert s["vms_running"] == 1 and s["gpus_running"] == ["bundled with a2-highgpu-1g"]
    assert (
        s["unattached_disk_gb"] == 500
        and s["unused_external_ips"] == 1
        and s["snapshot_stored_gb"] == 2.0
    )


def test_compute_reports_failed_section_not_failure(cloud: Any) -> None:
    for kind in ("instances", "disks", "addresses"):
        cloud.on("GET", rf"aggregated/{kind}", {"items": {}})
    cloud.on(
        "GET",
        r"global/snapshots",
        lambda p, b, t: (403, {"error": {"code": 403, "message": "nope"}}),
    )
    cloud.on("GET", r"global/images", {"items": []})
    out = inventory.compute(make(cloud), P)
    assert (
        out["errors"]["snapshots"]["error"] == "permission"
        and out["summary"]["vms"] == 0
    )


def test_access_flags(cloud: Any) -> None:
    cloud.on(
        "POST",
        r":getIamPolicy$",
        {
            "bindings": [
                {"role": "roles/owner", "members": ["user:forsythc@ucr.edu"]},
                {
                    "role": "roles/editor",
                    "members": [
                        "serviceAccount:111-compute@developer.gserviceaccount.com",
                        "user:someone@gmail.com",
                    ],
                },
                {
                    "role": "roles/viewer",
                    "members": ["allUsers", "deleted:user:x@ucr.edu?uid=1"],
                },
            ]
        },
    )
    out = iam.access(make(cloud), CFG, P)
    flags = {m["member"]: m["flags"] for m in out["flagged"]}
    assert "public" in flags["allUsers"]
    assert "outside_domain" in flags["user:someone@gmail.com"]
    assert (
        "default_compute_sa_is_editor"
        in flags["serviceAccount:111-compute@developer.gserviceaccount.com"]
    )
    assert "deleted_principal" in flags["deleted:user:x@ucr.edu?uid=1"]
    assert out["owners"] == ["user:forsythc@ucr.edu"]


def test_api_keys_never_fetch_key_strings(cloud: Any) -> None:
    cloud.on(
        "GET",
        r"apikeys.*/keys$",
        {
            "keys": [
                {
                    "uid": "u1",
                    "displayName": "open key",
                    "createTime": "2025-01-01T00:00:00Z",
                },
                {
                    "uid": "u2",
                    "displayName": "gemini",
                    "restrictions": {
                        "apiTargets": [
                            {"service": "generativelanguage.googleapis.com"}
                        ],
                        "serverKeyRestrictions": {},
                    },
                },
            ]
        },
    )
    cloud.on(
        "GET",
        r"timeSeries",
        {
            "timeSeries": [
                {
                    "metric": {"labels": {"credential_id": "apikey:u2"}},
                    "resource": {
                        "labels": {"service": "generativelanguage.googleapis.com"}
                    },
                    "points": [{"value": {"int64Value": "42"}}],
                }
            ]
        },
    )
    out = iam.api_keys(make(cloud), P)
    assert out["unrestricted"] == 1 and out["items"][0]["requests_30d"] == 42
    assert not any("keyString" in c["url"] for c in cloud.calls)


def test_exposure_finds_open_ports_and_public_bindings(cloud: Any) -> None:
    cloud.on(
        "GET",
        r"global/firewalls",
        {
            "items": [
                {
                    "name": "allow-ssh",
                    "sourceRanges": ["0.0.0.0/0"],
                    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                },
                {
                    "name": "internal",
                    "sourceRanges": ["10.0.0.0/8"],
                    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                },
                {
                    "name": "web",
                    "sourceRanges": ["0.0.0.0/0"],
                    "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
                },
            ]
        },
    )
    cloud.on(
        "GET",
        r"searchAllIamPolicies",
        {
            "results": [
                {
                    "resource": "//storage.googleapis.com/bucket-x",
                    "assetType": "storage.googleapis.com/Bucket",
                    "policy": {
                        "bindings": [
                            {
                                "role": "roles/storage.objectViewer",
                                "members": ["allUsers"],
                            }
                        ]
                    },
                }
            ]
        },
    )
    cloud.on("GET", r"searchAllResources", {"results": []})
    cloud.on(
        "GET",
        r"securitycenter",
        {
            "listFindingsResults": [
                {"finding": {"severity": "HIGH", "category": "OPEN_SSH_PORT"}}
            ]
        },
    )
    out = security.exposure(make(cloud), P)
    assert [f["rule"] for f in out["open_firewall_rules"]] == ["allow-ssh"]
    assert any("bucket-x" in r for r in out["risks"]) and any(
        "1 high" in r for r in out["risks"]
    )


def test_recommendations_only_ask_where_resources_are(cloud: Any) -> None:
    cloud.on(
        "GET",
        r"searchAllResources",
        {
            "results": [
                {"assetType": "compute.googleapis.com/Disk", "location": "us-west1-a"},
                {
                    "assetType": "compute.googleapis.com/Subnetwork",
                    "location": "europe-west1",
                },
            ]
        },
    )
    cloud.on(
        "GET",
        r"recommender.*IdleResourceRecommender",
        {
            "recommendations": [
                {
                    "description": "delete idle disk",
                    "primaryImpact": {
                        "category": "COST",
                        "costProjection": {
                            "cost": {"units": "-75", "nanos": -500000000},
                            "duration": "2592000s",
                        },
                    },
                    "content": {
                        "operationGroups": [
                            {
                                "operations": [
                                    {
                                        "action": "remove",
                                        "resource": "//compute/disks/d1",
                                    }
                                ]
                            }
                        ]
                    },
                }
            ]
        },
    )
    out = recommend.recommendations(make(cloud), P)
    assert out["asked"]["zones"] == ["us-west1-a"] and out["asked"]["regions"] == [
        "us-west1"
    ]
    assert not any("europe-west1" in c["url"] for c in cloud.calls)
    assert out["by_kind"]["idle_disk"]["monthly_saving"] == 75.5


def test_activity_filters_are_validated(cloud: Any) -> None:
    with pytest.raises(GcpError):
        ops.activity(make(cloud), P, principal='x" OR true OR "')
    cloud.on(
        "POST",
        r"entries:list$",
        {
            "entries": [
                {
                    "timestamp": "t",
                    "protoPayload": {
                        "methodName": "v1.compute.instances.delete",
                        "authenticationInfo": {"principalEmail": "a@ucr.edu"},
                    },
                }
            ]
        },
    )
    out = ops.activity(make(cloud), P, principal="a@ucr.edu")
    assert out["by_principal"] == {"a@ucr.edu": 1}
    assert 'principalEmail:"a@ucr.edu"' in cloud.calls[-1]["body"]["filter"]


def test_overview_turns_sections_into_findings(cloud: Any) -> None:
    cloud.on(
        "GET",
        r"/v3/projects/" + P + "$",
        {"projectId": P, "name": "projects/111", "state": "ACTIVE"},
    )
    cloud.on(
        "GET",
        r"billingInfo$",
        {"billingEnabled": True, "billingAccountName": "billingAccounts/x"},
    )
    cloud.on("GET", r"searchAllResources", {"results": []})
    cloud.on("GET", r"aggregated/instances", {"items": {}})
    cloud.on(
        "GET",
        r"aggregated/disks",
        {
            "items": {
                "zones/z-a": {"disks": [{"name": "d", "sizeGb": "2048", "users": []}]}
            }
        },
    )
    cloud.on("GET", r"aggregated/addresses", {"items": {}})
    cloud.on("GET", r"global/(snapshots|images)", {"items": []})
    cloud.on("GET", r"/services$", {"services": []})
    cloud.on(
        "POST",
        r":getIamPolicy$",
        {"bindings": [{"role": "roles/editor", "members": ["user:x@gmail.com"]}]},
    )
    cloud.on("GET", r"global/firewalls", {"items": []})
    cloud.on("GET", r"searchAllIamPolicies", {"results": []})
    cloud.on(
        "GET",
        r"securitycenter",
        lambda p, b, t: (
            403,
            {"error": {"code": 403, "message": "API has not been used"}},
        ),
    )
    cloud.on("POST", r"entries:list$", {"entries": []})
    cloud.on("GET", r"apikeys", {"keys": []})
    cloud.on("GET", r"timeSeries", {"timeSeries": []})
    out = overview.overview(make(cloud), IntelConfig(), P)
    texts = [f["text"] for f in out["findings"]]
    assert any("2,048 GB" in t for t in texts)
    assert any("x@gmail.com" in t for t in texts)
    # SCC being off is a note inside exposure, not a failed briefing
    assert (
        out["exposure"]["errors"]["security_command_center"]["error"] == "api_disabled"
    )


@pytest.mark.parametrize(
    "bad", ['x" OR true OR "', "a b", "", "x\nlogName=other", "a" * 300]
)
def test_log_filter_inputs_are_validated(cloud: Any, bad: str) -> None:
    for kw in ({"principal": bad}, {"method_contains": bad}):
        if not bad and "principal" in kw:
            continue  # empty means "no filter"
        if not bad:
            continue
        with pytest.raises(GcpError) as e:
            ops.activity(make(cloud), P, **kw)
        assert e.value.kind == "invalid"
    assert cloud.calls == []


def test_budget_spend_is_scoped_to_the_project(cloud: Any) -> None:
    seen: list[dict[str, Any]] = []
    cloud.on(
        "GET",
        r"cloudresourcemanager.*projects:search",
        {"projects": [{"projectId": P, "name": "projects/111"}]},
    )
    cloud.on("GET", r"billingbudgets.*/budgets$", {"budgets": []})

    def q(p: Any, body: Any, t: Any) -> Any:
        seen.append(body)
        return 200, _bq(
            [],
            [
                ("project", "STRING"),
                ("number", "STRING"),
                ("day", "DATE"),
                ("gross", "FLOAT"),
                ("credits", "FLOAT"),
            ],
        )

    cloud.on("POST", r"bigquery", q)
    billing.budgets(make(cloud), CFG, P)
    assert "project.id = @project" in seen[0]["query"]
