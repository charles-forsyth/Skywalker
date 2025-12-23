from __future__ import annotations

from functools import lru_cache
from typing import Any

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
)
from google.cloud import storage  # type: ignore # noqa: I001

# Shared Client Registry (Lazy-loaded and cached)


@lru_cache(maxsize=1)
def get_compute_instances_client() -> Any:
    return compute_v1.InstancesClient()


@lru_cache(maxsize=1)
def get_compute_images_client() -> Any:
    return compute_v1.ImagesClient()


@lru_cache(maxsize=1)
def get_compute_machine_images_client() -> Any:
    return compute_v1.MachineImagesClient()


@lru_cache(maxsize=1)
def get_compute_snapshots_client() -> Any:
    return compute_v1.SnapshotsClient()


@lru_cache(maxsize=1)
def get_firewalls_client() -> Any:
    return compute_v1.FirewallsClient()


@lru_cache(maxsize=1)
def get_networks_client() -> Any:
    return compute_v1.NetworksClient()


@lru_cache(maxsize=1)
def get_subnetworks_client() -> Any:
    return compute_v1.SubnetworksClient()


@lru_cache(maxsize=1)
def get_addresses_client() -> Any:
    return compute_v1.AddressesClient()


@lru_cache(maxsize=1)
def get_monitoring_client() -> Any:
    return monitoring_v3.MetricServiceClient()


@lru_cache(maxsize=1)
def get_asset_client() -> Any:
    return asset_v1.AssetServiceClient()


@lru_cache(maxsize=1)
def get_projects_client() -> Any:
    return resourcemanager_v3.ProjectsClient()


@lru_cache(maxsize=1)
def get_gke_client() -> Any:
    return container_v1.ClusterManagerClient()


@lru_cache(maxsize=1)
def get_sql_client() -> Any:
    from googleapiclient import discovery

    return discovery.build("sqladmin", "v1beta4", cache_discovery=False)


@lru_cache(maxsize=1)
def get_filestore_client() -> Any:
    return filestore_v1.CloudFilestoreManagerClient()


@lru_cache(maxsize=1)
def get_run_client() -> Any:
    return run_v2.ServicesClient()


@lru_cache(maxsize=1)
def get_iam_client() -> Any:
    return iam_admin_v1.IAMClient()


@lru_cache(maxsize=1)
def get_notebook_client() -> Any:
    return notebooks_v1.NotebookServiceClient()


@lru_cache(maxsize=1)
def get_storage_client() -> Any:
    return storage.Client()
