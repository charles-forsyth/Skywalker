import pytest

from skywalker.walkers.filestore import list_instances


def test_list_filestore_instances(mocker):
    # Mock the client
    mock_get = mocker.patch("skywalker.walkers.filestore.get_filestore_client")
    mock_client = mock_get.return_value

    # Mock Instance
    mock_inst = mocker.Mock()
    mock_inst.name = "projects/p/locations/us-central1/instances/my-nfs"

    # Mock Enums
    mock_inst.tier = mocker.Mock()
    mock_inst.tier.name = "BASIC_HDD"

    mock_inst.state = mocker.Mock()
    mock_inst.state.name = "READY"

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
    mock_client.list_instances.return_value = [mock_inst]

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
