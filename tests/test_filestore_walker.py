import pytest

from skywalker.core import memory
from skywalker.walkers.filestore import list_instances


@pytest.fixture(autouse=True)
def clear_cache():
    memory.clear()


def test_list_filestore_instances(mocker):
    # Mock the client
    mock_client = mocker.patch(
        "skywalker.walkers.filestore.filestore_v1.CloudFilestoreManagerClient"
    )

    # Mock Instance
    mock_inst = mocker.Mock()
    mock_inst.name = "projects/p/locations/us-central1/instances/my-nfs"
    mock_inst.tier = "TIER.BASIC_HDD"
    mock_inst.state = "STATE.READY"
    mock_inst.create_time = "2023-01-01"

    # Mock Networks
    mock_net = mocker.Mock()
    mock_net.ip_addresses = ["10.0.0.99"]
    mock_inst.networks = [mock_net]

    # Mock FileShare
    mock_share = mocker.Mock()
    mock_share.capacity_gb = 1024
    mock_inst.file_shares = [mock_share]

    # Setup return
    mock_client.return_value.list_instances.return_value = [mock_inst]

    # Call
    results = list_instances("test-proj", "us-central1")

    # Assert
    assert len(results) == 1
    fs = results[0]
    assert fs.name == "my-nfs"
    assert fs.tier == "BASIC_HDD"
    assert fs.state == "READY"
    assert fs.capacity_gb == 1024
    assert fs.ip_addresses == ["10.0.0.99"]
    assert fs.location == "us-central1"
