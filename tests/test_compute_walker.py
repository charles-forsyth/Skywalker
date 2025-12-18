import pytest

from skywalker.core import memory
from skywalker.walkers.compute import list_instances


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
    mock_disk.type = "pd-ssd"
    mock_disk.status = "READY"
    mock_disk.boot = True
    mock_instance.disks = [mock_disk]

    # Mock GPUs
    mock_acc = mocker.Mock()
    mock_acc.accelerator_type = "zones/us-west1-b/acceleratorTypes/nvidia-tesla-t4"
    mock_acc.accelerator_count = 1
    mock_instance.guest_accelerators = [mock_acc]

    # Mock Network
    mock_nic = mocker.Mock()
    mock_nic.network_ip = "10.0.0.1"
    mock_access = mocker.Mock()
    mock_access.nat_ip = "34.1.2.3"
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
