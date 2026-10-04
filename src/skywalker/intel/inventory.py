"""What exists in a project: Cloud Asset Inventory counts plus Compute detail.

Asset Inventory covers every region and service in one paged call, so nothing is
missed the way a fixed region list misses resources. Compute uses aggregated
lists (all zones at once).
"""

from __future__ import annotations

from typing import Any

from .gcp import Gcp
from .util import age_days, basename, clamp, project_id, sections, zone_to_region

ASSET = "https://cloudasset.googleapis.com/v1"
COMPUTE = "https://compute.googleapis.com/compute/v1"

# Asset types worth naming in a summary (the rest are counted under "other").
NOTABLE = {
    "compute.googleapis.com/Instance": "vm",
    "compute.googleapis.com/Disk": "disk",
    "compute.googleapis.com/Snapshot": "snapshot",
    "compute.googleapis.com/Image": "image",
    "compute.googleapis.com/Address": "ip_address",
    "storage.googleapis.com/Bucket": "bucket",
    "run.googleapis.com/Service": "cloud_run_service",
    "run.googleapis.com/Job": "cloud_run_job",
    "cloudfunctions.googleapis.com/CloudFunction": "cloud_function",
    "cloudfunctions.googleapis.com/Function": "cloud_function",
    "sqladmin.googleapis.com/Instance": "cloud_sql",
    "container.googleapis.com/Cluster": "gke_cluster",
    "file.googleapis.com/Instance": "filestore",
    "aiplatform.googleapis.com/Endpoint": "vertex_endpoint",
    "notebooks.googleapis.com/Instance": "workbench",
    "workstations.googleapis.com/Workstation": "workstation",
    "bigquery.googleapis.com/Dataset": "bq_dataset",
    "iam.googleapis.com/ServiceAccount": "service_account",
    "iam.googleapis.com/ServiceAccountKey": "service_account_key",
    "pubsub.googleapis.com/Topic": "pubsub_topic",
    "secretmanager.googleapis.com/Secret": "secret",
    "artifactregistry.googleapis.com/Repository": "artifact_repo",
}


def assets(gcp: Gcp, project: str, limit: int = 5000) -> list[dict[str, Any]]:
    pid = project_id(project)
    return list(
        gcp.paged(
            f"{ASSET}/projects/{pid}:searchAllResources", {}, "results", limit=limit
        )
    )


def summarize_assets(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_location: dict[str, int] = {}
    for r in rows:
        t = r.get("assetType", "")
        by_type[t] = by_type.get(t, 0) + 1
        loc = r.get("location", "") or "global"
        by_location[loc] = by_location.get(loc, 0) + 1
    notable: dict[str, int] = {}
    for t, n in by_type.items():
        if t in NOTABLE:
            notable[NOTABLE[t]] = notable.get(NOTABLE[t], 0) + n
    return {
        "resources": len(rows),
        "notable": dict(sorted(notable.items())),
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "by_location": dict(sorted(by_location.items(), key=lambda kv: -kv[1])),
    }


LOCATION_TYPES = {
    "compute.googleapis.com/Instance",
    "compute.googleapis.com/Disk",
    "compute.googleapis.com/Address",
    "compute.googleapis.com/Commitment",
    "sqladmin.googleapis.com/Instance",
    "file.googleapis.com/Instance",
}


def locations_in_use(rows: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """(zones, regions) where the project has billable compute-like resources.

    Only resource types recommenders cover count: an auto-mode default network
    puts a subnet in every region, which would otherwise mean asking ~40 regions.
    """
    zones, regions = set(), set()
    for r in rows:
        if r.get("assetType") not in LOCATION_TYPES:
            continue
        loc = r.get("location", "") or ""
        if loc.count("-") == 2 and loc[-2] == "-" and loc[-1].isalpha():
            zones.add(loc)
            regions.add(zone_to_region(loc))
        elif loc.count("-") == 1 and loc[-1].isdigit():
            regions.add(loc)
    return sorted(zones), sorted(regions)


def inventory(
    gcp: Gcp, project: str, asset_type: str = "", limit: int = 50
) -> dict[str, Any]:
    """Counts by type and location; with `asset_type`, list those resources."""
    rows = assets(gcp, project)
    out = summarize_assets(rows)
    out["project_id"] = project_id(project)
    if asset_type:
        want = asset_type.strip()
        hit = [
            {
                "name": r.get("displayName") or basename(r.get("name")),
                "type": r.get("assetType"),
                "location": r.get("location", ""),
                "state": r.get("state", ""),
                "created": r.get("createTime", ""),
                "labels": r.get("labels", {}) or {},
            }
            for r in rows
            if want in (r.get("assetType", ""), NOTABLE.get(r.get("assetType", ""), ""))
        ]
        lim = clamp(limit, 1, 500)
        out["items"] = hit[:lim]
        out["items_truncated"] = len(hit) > lim
    # by_type can be long; keep the top 40
    bt = out["by_type"]
    if len(bt) > 40:
        out["by_type"] = dict(list(bt.items())[:40])
        out["by_type_truncated"] = True
    return out


# --- Compute detail ----------------------------------------------------------


def _machine(url: str) -> str:
    return basename(url)


def _gpus(inst: dict[str, Any]) -> list[str]:
    out = []
    for a in inst.get("guestAccelerators", []) or []:
        out.append(
            f"{a.get('acceleratorCount', 1)}x {basename(a.get('acceleratorType'))}"
        )
    mt = _machine(inst.get("machineType", ""))
    # A2/A3/G2 machine types carry GPUs without guestAccelerators.
    if not out and mt.split("-")[0] in ("a2", "a3", "a4", "g2", "g4"):
        out.append(f"bundled with {mt}")
    return out


def instances(gcp: Gcp, project: str) -> list[dict[str, Any]]:
    pid = project_id(project)
    out = []
    for scope, i in gcp.aggregated(
        f"{COMPUTE}/projects/{pid}/aggregated/instances", "instances"
    ):
        ext = [
            ac.get("natIP")
            for ni in i.get("networkInterfaces", []) or []
            for ac in ni.get("accessConfigs", []) or []
            if ac.get("natIP")
        ]
        sa = [s.get("email", "") for s in i.get("serviceAccounts", []) or []]
        out.append(
            {
                "name": i.get("name"),
                "zone": basename(scope),
                "status": i.get("status"),
                "machine_type": _machine(i.get("machineType", "")),
                "gpus": _gpus(i),
                "spot": (i.get("scheduling", {}) or {}).get("provisioningModel")
                == "SPOT"
                or bool((i.get("scheduling", {}) or {}).get("preemptible")),
                "external_ips": ext,
                "service_accounts": sa,
                "created": i.get("creationTimestamp"),
                "last_start": i.get("lastStartTimestamp"),
                "last_stop": i.get("lastStopTimestamp"),
                "labels": i.get("labels", {}) or {},
            }
        )
    return out


def disks(gcp: Gcp, project: str) -> list[dict[str, Any]]:
    pid = project_id(project)
    out = []
    for scope, d in gcp.aggregated(
        f"{COMPUTE}/projects/{pid}/aggregated/disks", "disks"
    ):
        out.append(
            {
                "name": d.get("name"),
                "location": basename(scope),
                "size_gb": int(d.get("sizeGb", 0) or 0),
                "type": basename(d.get("type")),
                "attached_to": [basename(u) for u in d.get("users", []) or []],
                "status": d.get("status"),
                "created": d.get("creationTimestamp"),
                "last_detach": d.get("lastDetachTimestamp"),
                "source_image": basename(d.get("sourceImage")),
            }
        )
    return out


def addresses(gcp: Gcp, project: str) -> list[dict[str, Any]]:
    pid = project_id(project)
    out = []
    for scope, a in gcp.aggregated(
        f"{COMPUTE}/projects/{pid}/aggregated/addresses", "addresses"
    ):
        out.append(
            {
                "name": a.get("name"),
                "address": a.get("address"),
                "region": basename(scope),
                "type": a.get("addressType", "EXTERNAL"),
                "status": a.get("status"),
                "users": [basename(u) for u in a.get("users", []) or []],
                "created": a.get("creationTimestamp"),
            }
        )
    return out


def snapshots(gcp: Gcp, project: str) -> list[dict[str, Any]]:
    pid = project_id(project)
    out = []
    for s in gcp.paged(
        f"{COMPUTE}/projects/{pid}/global/snapshots",
        {},
        "items",
        limit=5000,
        page_size_param="maxResults",
    ):
        out.append(
            {
                "name": s.get("name"),
                "disk_gb": int(s.get("diskSizeGb", 0) or 0),
                "stored_gb": round(int(s.get("storageBytes", 0) or 0) / 1024**3, 1),
                "source_disk": basename(s.get("sourceDisk")),
                "auto": bool(s.get("autoCreated")),
                "created": s.get("creationTimestamp"),
            }
        )
    return out


def images(gcp: Gcp, project: str) -> list[dict[str, Any]]:
    pid = project_id(project)
    out = []
    for s in gcp.paged(
        f"{COMPUTE}/projects/{pid}/global/images",
        {},
        "items",
        limit=2000,
        page_size_param="maxResults",
    ):
        out.append(
            {
                "name": s.get("name"),
                "archive_gb": round(
                    int(s.get("archiveSizeBytes", 0) or 0) / 1024**3, 1
                ),
                "created": s.get("creationTimestamp"),
                "status": s.get("status"),
            }
        )
    return out


def compute(gcp: Gcp, project: str, limit: int = 50) -> dict[str, Any]:
    """VMs, GPUs, disks, IPs, snapshots and images across every zone."""
    pid = project_id(project)
    got, errors = sections(
        {
            "instances": lambda: instances(gcp, pid),
            "disks": lambda: disks(gcp, pid),
            "addresses": lambda: addresses(gcp, pid),
            "snapshots": lambda: snapshots(gcp, pid),
            "images": lambda: images(gcp, pid),
        }
    )
    lim = clamp(limit, 1, 500)
    inst = got.get("instances", [])
    running = [i for i in inst if i["status"] == "RUNNING"]
    dsk = got.get("disks", [])
    snaps = got.get("snapshots", [])
    out: dict[str, Any] = {
        "project_id": pid,
        "summary": {
            "vms": len(inst),
            "vms_running": len(running),
            "vms_with_gpu": sum(1 for i in inst if i["gpus"]),
            "gpus_running": [g for i in running for g in i["gpus"]],
            "vms_with_external_ip": sum(1 for i in inst if i["external_ips"]),
            "disks": len(dsk),
            "disk_gb": sum(d["size_gb"] for d in dsk),
            "unattached_disks": sum(1 for d in dsk if not d["attached_to"]),
            "unattached_disk_gb": sum(
                d["size_gb"] for d in dsk if not d["attached_to"]
            ),
            "static_ips": len(got.get("addresses", [])),
            "unused_external_ips": sum(
                1
                for a in got.get("addresses", [])
                if a["status"] == "RESERVED" and a["type"] == "EXTERNAL"
            ),
            "snapshots": len(snaps),
            "snapshot_stored_gb": round(sum(s["stored_gb"] for s in snaps), 1),
            "custom_images": len(got.get("images", [])),
        },
        "instances": sorted(inst, key=lambda i: (i["status"] != "RUNNING", i["name"]))[
            :lim
        ],
        "disks": sorted(dsk, key=lambda d: (bool(d["attached_to"]), -d["size_gb"]))[
            :lim
        ],
        "addresses": got.get("addresses", [])[:lim],
        "snapshots": sorted(snaps, key=lambda s: -s["stored_gb"])[:lim],
        "images": got.get("images", [])[:lim],
    }
    out["truncated"] = any(
        len(got.get(k, [])) > lim
        for k in ("instances", "disks", "addresses", "snapshots", "images")
    )
    if errors:
        out["errors"] = errors
    for i in out["instances"]:
        if i["status"] != "RUNNING" and i.get("last_stop"):
            i["stopped_days"] = age_days(i["last_stop"])
    return out
