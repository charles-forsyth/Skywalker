from google.cloud import filestore_v1
from tenacity import retry

from ..clients import get_filestore_client
from ..core import RETRY_CONFIG
from ..schemas.filestore import GCPFilestoreInstance


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_instances(project_id: str, location: str) -> list[GCPFilestoreInstance]:
    """
    Lists all Filestore instances in a specific location (region or zone).
    """
    client = get_filestore_client()
    parent = f"projects/{project_id}/locations/{location}"

    results = []
    try:
        # Check: The parent must be a location.
        for instance in client.list_instances(parent=parent):
            # Extract IPs
            ips = [n.ip_addresses[0] for n in instance.networks if n.ip_addresses]

            # Clean tier and state names
            if hasattr(instance.tier, "name"):
                tier_str = instance.tier.name
            else:
                try:
                    tier_str = filestore_v1.Instance.Tier(instance.tier).name
                except Exception:
                    tier_str = str(instance.tier)

            if hasattr(instance.state, "name"):
                state_str = instance.state.name
            else:
                try:
                    state_str = filestore_v1.Instance.State(instance.state).name
                except Exception:
                    state_str = str(instance.state)

            capacity = 0
            if instance.file_shares:
                capacity = instance.file_shares[0].capacity_gb

            results.append(
                GCPFilestoreInstance(
                    name=instance.name.split("/")[-1],
                    tier=tier_str,
                    state=state_str,
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
