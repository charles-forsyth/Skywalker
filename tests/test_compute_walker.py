import pytest

from skywalker.core import memory
from skywalker.walkers.compute import (
    list_images,
    list_instances,
    list_machine_images,
    list_snapshots,
)


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear joblib caching for all tests in this module."""
    memory.clear()


def test_list_instances_deep_mock(mocker):
    # Mock the InstancesClient
    mock_client = mocker.patch("skywalker.walkers.compute.compute_v1.InstancesClient")

    # Create a mock instance object
    mock_instance = mocker.Mock()
    mock_instance.name = "test-deep-instance"
    mock_instance.id = 12345
    mock_instance.status = "RUNNING"
    mock_instance.machine_type = "zones/us-west1-b/machineTypes/n2-standard-4"
    mock_instance.creation_timestamp = "2023-01-01T12:00:00.000-07:00"
    mock_instance.labels = {"env": "prod"}

    # Mock Disks
    mock_disk = mocker.Mock()
    mock_disk.device_name = "boot-disk"
    mock_disk.disk_size_gb = 100
    mock_disk.type_ = "PERSISTENT"
    mock_disk.boot = True
    mock_instance.disks = [mock_disk]

    # Mock GPUs
    mock_acc = mocker.Mock()
    mock_acc.accelerator_type = "zones/us-west1-b/acceleratorTypes/nvidia-tesla-t4"
    mock_acc.accelerator_count = 1
    mock_instance.guest_accelerators = [mock_acc]

    # Mock Network
    mock_nic = mocker.Mock()
    mock_nic.network_i_p = "10.0.0.1"
    mock_access = mocker.Mock()
    mock_access.nat_i_p = "34.1.2.3"
    mock_nic.access_configs = [mock_access]
    mock_instance.network_interfaces = [mock_nic]

    # Configure the mock client
    mock_client.return_value.list.return_value = [mock_instance]

    # Call the function
    instances = list_instances(project_id="test-project", zone="us-west1-b")

    # Assertions
    assert len(instances) == 1
    inst = instances[0]

    assert inst.name == "test-deep-instance"
    assert inst.machine_type == "n2-standard-4"
    assert len(inst.disks) == 1
    assert inst.disks[0].size_gb == 100
    assert inst.disks[0].boot is True

    assert len(inst.gpus) == 1
    assert inst.gpus[0].name == "nvidia-tesla-t4"

    assert inst.internal_ip == "10.0.0.1"
    assert inst.external_ip == "34.1.2.3"

    mock_client.return_value.list.assert_called_once()


def test_list_images_mock(mocker):
    mock_client = mocker.patch("skywalker.walkers.compute.compute_v1.ImagesClient")

    mock_img = mocker.Mock()
    mock_img.name = "my-custom-image"
    mock_img.id = 999
    mock_img.disk_size_gb = 50
    mock_img.status = "READY"
    mock_img.archive_size_bytes = 1024 * 1024 * 1024  # 1GB
    mock_img.creation_timestamp = "2023-01-01"

    mock_client.return_value.list.return_value = [mock_img]

    images = list_images("test-project")
    assert len(images) == 1
    assert images[0].name == "my-custom-image"
    assert images[0].archive_size_bytes == 1073741824


def test_list_machine_images_mock(mocker):
    mock_client = mocker.patch(
        "skywalker.walkers.compute.compute_v1.MachineImagesClient"
    )

    mock_img = mocker.Mock()
    mock_img.name = "my-machine-image"
    mock_img.id = 777
    mock_img.status = "READY"
    mock_img.total_storage_bytes = 2048 * 1024 * 1024  # 2GB
    mock_img.creation_timestamp = "2023-03-01"

    mock_client.return_value.list.return_value = [mock_img]

    images = list_machine_images("test-project")
    assert len(images) == 1
    assert images[0].name == "my-machine-image"
    assert images[0].total_storage_bytes == 2147483648


def test_list_snapshots_mock(mocker):
    mock_client = mocker.patch("skywalker.walkers.compute.compute_v1.SnapshotsClient")

    mock_snap = mocker.Mock()
    mock_snap.name = "my-snapshot"
    mock_snap.id = 888
    mock_snap.disk_size_gb = 200
    mock_snap.status = "READY"
    mock_snap.storage_bytes = 500000000
    mock_snap.creation_timestamp = "2023-02-01"

    mock_client.return_value.list.return_value = [mock_snap]

    snaps = list_snapshots("test-project")
    assert len(snaps) == 1
    assert snaps[0].name == "my-snapshot"
    assert snaps[0].disk_size_gb == 200
