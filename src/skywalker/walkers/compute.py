from google.cloud import compute_v1
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


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_instances(project_id: str, zone: str) -> list[GCPComputeInstance]:
    """
    Lists all instances in a given zone for a project with deep details.
    Cached by joblib and retried by tenacity on failure.
    """
    instance_client = compute_v1.InstancesClient()
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
                creation_timestamp=img.creation_timestamp, # type: ignore[arg-type]
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
                creation_timestamp=img.creation_timestamp, # type: ignore[arg-type]
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
                creation_timestamp=snap.creation_timestamp, # type: ignore[arg-type]
                disk_size_gb=snap.disk_size_gb,
                status=snap.status,
                storage_bytes=snap.storage_bytes,
            )
        )
    return results
