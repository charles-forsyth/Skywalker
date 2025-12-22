from functools import lru_cache
from typing import Any

# Import GCP clients
from google.cloud import (
    asset_v1,
    compute_v1,
    container_v1,
    filestore_v1,
    iam_admin_v1,
    monitoring_v3,
    notebooks_v1,
    resourcemanager_v3,
    run_v2,
    storage,
)

# Shared Client Registry (Lazy-loaded and cached)


@lru_cache(maxsize=1)
def get_compute_instances_client() -> compute_v1.InstancesClient:
    return compute_v1.InstancesClient()


@lru_cache(maxsize=1)
def get_compute_images_client() -> compute_v1.ImagesClient:
    return compute_v1.ImagesClient()


@lru_cache(maxsize=1)
def get_compute_machine_images_client() -> compute_v1.MachineImagesClient:
    return compute_v1.MachineImagesClient()


@lru_cache(maxsize=1)
def get_compute_snapshots_client() -> compute_v1.SnapshotsClient:
    return compute_v1.SnapshotsClient()


@lru_cache(maxsize=1)
def get_firewalls_client() -> compute_v1.FirewallsClient:
    return compute_v1.FirewallsClient()


@lru_cache(maxsize=1)
def get_networks_client() -> compute_v1.NetworksClient:
    return compute_v1.NetworksClient()


@lru_cache(maxsize=1)
def get_subnetworks_client() -> compute_v1.SubnetworksClient:
    return compute_v1.SubnetworksClient()


@lru_cache(maxsize=1)
def get_addresses_client() -> compute_v1.AddressesClient:
    return compute_v1.AddressesClient()


@lru_cache(maxsize=1)
def get_monitoring_client() -> monitoring_v3.MetricServiceClient:
    return monitoring_v3.MetricServiceClient()


@lru_cache(maxsize=1)
def get_asset_client() -> asset_v1.AssetServiceClient:
    return asset_v1.AssetServiceClient()


@lru_cache(maxsize=1)
def get_projects_client() -> resourcemanager_v3.ProjectsClient:
    return resourcemanager_v3.ProjectsClient()


@lru_cache(maxsize=1)
def get_gke_client() -> container_v1.ClusterManagerClient:
    return container_v1.ClusterManagerClient()


@lru_cache(maxsize=1)
def get_sql_client() -> Any:
    from googleapiclient import discovery

    return discovery.build("sqladmin", "v1beta4", cache_discovery=False)


@lru_cache(maxsize=1)
def get_filestore_client() -> filestore_v1.CloudFilestoreManagerClient:
    return filestore_v1.CloudFilestoreManagerClient()


@lru_cache(maxsize=1)
def get_run_client() -> run_v2.ServicesClient:
    return run_v2.ServicesClient()


@lru_cache(maxsize=1)
def get_iam_client() -> iam_admin_v1.IAMClient:
    return iam_admin_v1.IAMClient()


@lru_cache(maxsize=1)
def get_notebook_client() -> notebooks_v1.NotebookServiceClient:
    return notebooks_v1.NotebookServiceClient()


@lru_cache(maxsize=1)
def get_storage_client() -> storage.Client:
    return storage.Client()
