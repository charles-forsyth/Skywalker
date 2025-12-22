from google.cloud import container_v1
from tenacity import retry

from ..clients import get_gke_client
from ..core import RETRY_CONFIG
from ..logger import logger
from ..schemas.gke import GCPCluster, GCPNodePool


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_clusters(project_id: str, location: str) -> list[GCPCluster]:
    """
    Lists all GKE clusters in a specific location (region or zone).
    """
    client = get_gke_client()
    parent = f"projects/{project_id}/locations/{location}"

    results = []
    try:
        request = container_v1.ListClustersRequest(parent=parent)
        response = client.list_clusters(request=request)

        for cluster in response.clusters:
            node_pools = []
            for np in cluster.node_pools:
                node_pools.append(
                    GCPNodePool(
                        name=np.name,
                        machine_type=np.config.machine_type,
                        disk_size_gb=np.config.disk_size_gb,
                        node_count=np.initial_node_count,
                        version=np.version,
                        status=str(np.status.name),
                    )
                )

            results.append(
                GCPCluster(
                    name=cluster.name,
                    location=cluster.location,
                    status=str(cluster.status.name),
                    version=cluster.current_master_version,
                    endpoint=cluster.endpoint,
                    node_pools=node_pools,
                    network=cluster.network,
                    subnetwork=cluster.subnetwork,
                )
            )
    except Exception as e:
        logger.warning(f"Failed to list clusters in {location} for {project_id}: {e}")

    return results