from google.cloud import container_v1
from tenacity import retry

from ..core import RETRY_CONFIG, memory
from ..schemas.gke import GCPCluster, GCPNodePool


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_clusters(project_id: str, location: str) -> list[GCPCluster]:
    """
    Lists all GKE clusters in a specific location (region or zone).
    """
    client = container_v1.ClusterManagerClient()
    parent = f"projects/{project_id}/locations/{location}"

    request = container_v1.ListClustersRequest(parent=parent)
    response = client.list_clusters(request=request)

    results = []
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

    return results
