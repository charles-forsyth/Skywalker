from typing import Any

from google.cloud import asset_v1
from tenacity import retry

from ..core import RETRY_CONFIG, memory


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def search_all_instances(scope: str) -> dict[str, dict[str, Any]]:
    """
    Searches for all Compute Instances within the given scope (Project, Folder, or Org).
    Returns a dict mapping instance_id -> {name, machine_type, ...}
    """
    client = asset_v1.AssetServiceClient()

    # Ensure scope is formatted correctly
    if (
        not scope.startswith("projects/")
        and not scope.startswith("folders/")
        and not scope.startswith("organizations/")
    ):
        # Assume project ID if bare string
        scope = f"projects/{scope}"

    results = {}

    try:
        # Search for GCE Instances
        response = client.search_all_resources(
            request={
                "scope": scope,
                "asset_types": ["compute.googleapis.com/Instance"],
                "read_mask": "name,displayName,additionalAttributes",
            }
        )

                for resource in response:
                    # resource.name is the full asset name
                    # resource.display_name is the VM name
                    # resource.additional_attributes is a Struct
                    attrs = resource.additional_attributes
                    raw_id = attrs.get("id")
        
                    if raw_id:
                        instance_id = str(raw_id)
                        results[instance_id] = {
                            "name": resource.display_name,
                            "machine_type": attrs.get("machineType", "unknown"),
                            "zone": resource.location,
                            "project": resource.project,
                        }
    except Exception:
        # Permission denied or API disabled
        pass

    return results
