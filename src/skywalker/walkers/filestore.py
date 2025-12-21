from google.cloud import filestore_v1
from tenacity import retry

from ..core import RETRY_CONFIG, memory
from ..schemas.filestore import GCPFilestoreInstance


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_instances(project_id: str, location: str) -> list[GCPFilestoreInstance]:
    """
    Lists all Filestore instances in a specific location (region or zone).
    """
    client = filestore_v1.CloudFilestoreManagerClient()
    parent = f"projects/{project_id}/locations/{location}"

    results = []
    try:
        # Check: The parent must be a location.
        for instance in client.list_instances(parent=parent):
            # Extract IPs
            ips = [n.ip_addresses[0] for n in instance.networks if n.ip_addresses]

            # Clean tier name (e.g. Tier.BASIC_HDD)
            tier_str = str(instance.tier).split(".")[-1]

            capacity = 0
            if instance.file_shares:
                capacity = instance.file_shares[0].capacity_gb

            results.append(
                GCPFilestoreInstance(
                    name=instance.name.split("/")[-1],
                    tier=tier_str,
                    state=str(instance.state).split(".")[-1],
                    capacity_gb=capacity,
                    ip_addresses=ips,
                    create_time=instance.create_time,
                    location=location,
                )
            )
    except Exception:
        # If the region has no instances or API is disabled, just return empty
        pass

    return results
