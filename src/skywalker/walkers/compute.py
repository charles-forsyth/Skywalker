import time

from google.cloud import compute_v1, monitoring_v3
from tenacity import retry

from ..core import RETRY_CONFIG, memory
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
    Fetches recent CPU and Memory metrics for all instances in a zone.
    Returns a dict mapping instance_id -> { 'cpu': float, 'mem': float }
    """
    client = monitoring_v3.MetricServiceClient()
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
    except Exception:
        pass

    # 2. Memory Usage (requires Ops Agent for deep metrics)
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
    except Exception:
        pass

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
                # GPU metrics can be per-GPU (device_id label)
                # We will take the MAX utilization of any GPU on the instance
                val = ts.points[0].value.double_value
                inst_data = metrics_map.setdefault(instance_id, {})
                current_max = inst_data.get("gpu_util", 0.0)
                inst_data["gpu_util"] = max(current_max, val)
    except Exception:
        pass

    # 4. GPU Memory Usage (Ops Agent)
    # The metric agent.googleapis.com/gpu/memory/utilization exists!
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
                val = ts.points[0].value.double_value * 100  # It returns 0.0-1.0
                inst_data = metrics_map.setdefault(instance_id, {})
                current_max = inst_data.get("gpu_mem", 0.0)
                inst_data["gpu_mem"] = max(current_max, val)
    except Exception:
        pass

    return metrics_map


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_instances(
    project_id: str, zone: str, include_metrics: bool = False
) -> list[GCPComputeInstance]:
    """
    Lists all instances in a given zone for a project with deep details.
    Cached by joblib and retried by tenacity on failure.
    """
    instance_client = compute_v1.InstancesClient()
    request = compute_v1.ListInstancesRequest(project=project_id, zone=zone)

    results = []

    # Optional metrics fetch for the entire zone
    metrics = {}
    if include_metrics:
        metrics = _fetch_performance_metrics(project_id, zone)

    for instance in instance_client.list(request=request):
        # ... (rest of the logic remains same, just update the constructor)
        iid = str(instance.id)
        inst_metrics = metrics.get(iid, {})
        # 1. Clean Machine Type
        m_type = instance.machine_type
        machine_type_clean = m_type.split("/")[-1] if m_type else "unknown"

        # 2. Extract GPUs
        gpus = []
        if instance.guest_accelerators:
            for acc in instance.guest_accelerators:
                # accelerator_type is a URL, e.g. .../nvidia-tesla-t4
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
                        type=str(d.type_),  # Use type_ to avoid reserved word
                        boot=d.boot,
                    )
                )

        # 4. Extract IPs
        internal_ip = None
        external_ip = None
        if instance.network_interfaces:
            # Usually the first interface is the primary one
            nic = instance.network_interfaces[0]
            internal_ip = nic.network_i_p
            if nic.access_configs:
                # Access configs hold external IPs (like NAT)
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
                cpu_utilization=inst_metrics.get("cpu"),
                memory_usage=inst_metrics.get("mem"),
                gpu_utilization=inst_metrics.get("gpu_util"),
                gpu_memory_usage=inst_metrics.get("gpu_mem"),
            )
        )

    return results


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_images(project_id: str) -> list[GCPImage]:
    """
    Lists all custom images in a project.
    """
    image_client = compute_v1.ImagesClient()
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


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_machine_images(project_id: str) -> list[GCPMachineImage]:
    """
    Lists all Machine Images (VM Backups) in a project.
    """
    client = compute_v1.MachineImagesClient()
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


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_snapshots(project_id: str) -> list[GCPSnapshot]:
    """
    Lists all disk snapshots in a project.
    """
    snapshot_client = compute_v1.SnapshotsClient()
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
