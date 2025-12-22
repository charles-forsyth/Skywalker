import time

from google.cloud import compute_v1, monitoring_v3
from tenacity import retry

from ..clients import (
    get_compute_images_client,
    get_compute_instances_client,
    get_compute_machine_images_client,
    get_compute_snapshots_client,
    get_monitoring_client,
)
from ..core import RETRY_CONFIG
from ..logger import logger
from ..schemas.compute import (
    GCPComputeInstance,
    GCPDisk,
    GCPGpu,
    GCPImage,
    GCPMachineImage,
    GCPSnapshot,
)


def _fetch_performance_metrics(
    project_id: str, zone: str
) -> dict[str, dict[str, float]]:
    """
    Fetches recent CPU, Memory, and GPU metrics for all instances in a zone.
    Returns a dict mapping instance_id -> { 'cpu': float, 'mem': float, ... }
    """
    client = get_monitoring_client()
    project_name = f"projects/{project_id}"

    # Last 10 minutes to ensure we catch a data point
    now = time.time()
    seconds = int(now)
    nanos = int((now - seconds) * 10**9)
    interval = monitoring_v3.TimeInterval(
        {
            "end_time": {"seconds": seconds, "nanos": nanos},
            "start_time": {"seconds": (seconds - 600), "nanos": nanos},
        }
    )

    metrics_map: dict[str, dict[str, float]] = {}

    # 1. CPU Utilization
    try:
        cpu_filter = (
            'metric.type = "compute.googleapis.com/instance/cpu/utilization" '
            f'AND resource.labels.zone = "{zone}"'
        )
        cpu_results = client.list_time_series(
            request={
                "name": project_name,
                "filter": cpu_filter,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            }
        )
        for ts in cpu_results:
            instance_id = ts.resource.labels.get("instance_id")
            if instance_id and ts.points:
                metrics_map.setdefault(instance_id, {})["cpu"] = (
                    ts.points[0].value.double_value * 100
                )
    except Exception as e:
        logger.debug(f"Failed to fetch CPU metrics for {zone}: {e}")

    # 2. Memory Usage (requires Ops Agent)
    try:
        mem_filter = (
            'metric.type = "agent.googleapis.com/memory/percent_used" '
            f'AND resource.labels.zone = "{zone}"'
        )
        mem_results = client.list_time_series(
            request={
                "name": project_name,
                "filter": mem_filter,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            }
        )
        for ts in mem_results:
            instance_id = ts.resource.labels.get("instance_id")
            if instance_id and ts.points:
                metrics_map.setdefault(instance_id, {})["mem"] = ts.points[
                    0
                ].value.double_value
    except Exception as e:
        logger.debug(f"Failed to fetch Memory metrics for {zone}: {e}")

    # 3. GPU Utilization (Ops Agent)
    try:
        gpu_util_filter = (
            'metric.type = "agent.googleapis.com/gpu/utilization" '
            f'AND resource.labels.zone = "{zone}"'
        )
        gpu_util_results = client.list_time_series(
            request={
                "name": project_name,
                "filter": gpu_util_filter,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            }
        )
        for ts in gpu_util_results:
            instance_id = ts.resource.labels.get("instance_id")
            if instance_id and ts.points:
                val = ts.points[0].value.double_value
                inst_data = metrics_map.setdefault(instance_id, {})
                current_max = inst_data.get("gpu_util", 0.0)
                inst_data["gpu_util"] = max(current_max, val)
    except Exception as e:
        logger.debug(f"Failed to fetch GPU utilization for {zone}: {e}")

    # 4. GPU Memory (Ops Agent)
    try:
        gpu_mem_util_filter = (
            'metric.type = "agent.googleapis.com/gpu/memory/utilization" '
            f'AND resource.labels.zone = "{zone}"'
        )
        gpu_mem_results = client.list_time_series(
            request={
                "name": project_name,
                "filter": gpu_mem_util_filter,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            }
        )
        for ts in gpu_mem_results:
            instance_id = ts.resource.labels.get("instance_id")
            if instance_id and ts.points:
                val = ts.points[0].value.double_value * 100
                inst_data = metrics_map.setdefault(instance_id, {})
                current_max = inst_data.get("gpu_mem", 0.0)
                inst_data["gpu_mem"] = max(current_max, val)
    except Exception as e:
        logger.debug(f"Failed to fetch GPU Memory metrics for {zone}: {e}")

    return metrics_map


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def _list_instances_inventory(
    project_id: str, zone: str
) -> list[GCPComputeInstance]:
    """
    Fetches raw inventory of instances. Cached.
    """
    instance_client = get_compute_instances_client()
    request = compute_v1.ListInstancesRequest(project=project_id, zone=zone)

    results = []

    for instance in instance_client.list(request=request):
        # 1. Clean Machine Type
        m_type = instance.machine_type
        machine_type_clean = m_type.split("/")[-1] if m_type else "unknown"

        # 2. Extract GPUs
        gpus = []
        if instance.guest_accelerators:
            for acc in instance.guest_accelerators:
                acc_type = acc.accelerator_type.split("/")[-1]
                gpus.append(
                    GCPGpu(name=acc_type, count=acc.accelerator_count, type=acc_type)
                )

        # 3. Extract Disks
        disks = []
        if instance.disks:
            for d in instance.disks:
                disks.append(
                    GCPDisk(
                        name=d.device_name or "unknown",
                        size_gb=d.disk_size_gb,
                        type=str(d.type_),
                        boot=d.boot,
                    )
                )

        # 4. Extract IPs
        internal_ip = None
        external_ip = None
        if instance.network_interfaces:
            nic = instance.network_interfaces[0]
            internal_ip = nic.network_i_p
            if nic.access_configs:
                external_ip = nic.access_configs[0].nat_i_p

        results.append(
            GCPComputeInstance(
                name=instance.name,
                id=str(instance.id),
                status=instance.status,
                machine_type=machine_type_clean,
                zone=zone,
                creation_timestamp=instance.creation_timestamp,  # type: ignore[arg-type]
                labels=dict(instance.labels) if instance.labels else {},
                disks=disks,
                gpus=gpus,
                internal_ip=internal_ip,
                external_ip=external_ip,
            )
        )

    return results


def list_instances(
    project_id: str, zone: str, include_metrics: bool = False
) -> list[GCPComputeInstance]:
    """
    Public API: Lists instances, optionally enriched with live metrics.
    Inventory is cached; Metrics are NOT cached.
    """
    # 1. Get Inventory (Cached)
    instances = _list_instances_inventory(project_id, zone)

    # 2. Get Metrics (Live) and Merge
    if include_metrics:
        metrics = _fetch_performance_metrics(project_id, zone)
        for inst in instances:
            if inst.id in metrics:
                m = metrics[inst.id]
                inst.cpu_utilization = m.get("cpu")
                inst.memory_usage = m.get("mem")
                inst.gpu_utilization = m.get("gpu_util")
                inst.gpu_memory_usage = m.get("gpu_mem")

    return instances


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_images(project_id: str) -> list[GCPImage]:
    """
    Lists all custom images in a project.
    """
    image_client = get_compute_images_client()
    request = compute_v1.ListImagesRequest(project=project_id)

    results = []
    for img in image_client.list(request=request):
        results.append(
            GCPImage(
                name=img.name,
                id=str(img.id),
                creation_timestamp=img.creation_timestamp,  # type: ignore[arg-type]
                disk_size_gb=img.disk_size_gb,
                status=img.status,
                archive_size_bytes=img.archive_size_bytes,
            )
        )
    return results


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_machine_images(project_id: str) -> list[GCPMachineImage]:
    """
    Lists all Machine Images (VM Backups) in a project.
    """
    client = get_compute_machine_images_client()
    request = compute_v1.ListMachineImagesRequest(project=project_id)

    results = []
    for img in client.list(request=request):
        results.append(
            GCPMachineImage(
                name=img.name,
                id=str(img.id),
                creation_timestamp=img.creation_timestamp,  # type: ignore[arg-type]
                status=img.status,
                total_storage_bytes=img.total_storage_bytes,
            )
        )
    return results


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_snapshots(project_id: str) -> list[GCPSnapshot]:
    """
    Lists all disk snapshots in a project.
    """
    snapshot_client = get_compute_snapshots_client()
    request = compute_v1.ListSnapshotsRequest(project=project_id)

    results = []
    for snap in snapshot_client.list(request=request):
        results.append(
            GCPSnapshot(
                name=snap.name,
                id=str(snap.id),
                creation_timestamp=snap.creation_timestamp,  # type: ignore[arg-type]
                disk_size_gb=snap.disk_size_gb,
                status=snap.status,
                storage_bytes=snap.storage_bytes,
            )
        )
    return results