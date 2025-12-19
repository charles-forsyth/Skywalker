import pytest

from skywalker.core import memory
from skywalker.walkers.network import get_network_report


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear joblib caching for all tests in this module."""
    memory.clear()


def test_get_network_report_mock(mocker):
    # Mock Clients
    mock_fw_client = mocker.patch(
        "skywalker.walkers.network.compute_v1.FirewallsClient"
    )
    mock_net_client = mocker.patch(
        "skywalker.walkers.network.compute_v1.NetworksClient"
    )
    mock_subnet_client = mocker.patch(
        "skywalker.walkers.network.compute_v1.SubnetworksClient"
    )
    mock_addr_client = mocker.patch(
        "skywalker.walkers.network.compute_v1.AddressesClient"
    )

    # Mock Firewall
    mock_fw = mocker.Mock()
    mock_fw.name = "default-allow-ssh"
    mock_fw.network = "global/networks/default"
    mock_fw.direction = "INGRESS"
    mock_fw.priority = 65534
    mock_fw.allowed = [mocker.Mock(IP_protocol="tcp", ports=["22"])]
    mock_fw.source_ranges = ["0.0.0.0/0"]
    mock_fw.target_tags = ["ssh-server"]
    mock_fw_client.return_value.list.return_value = [mock_fw]

    # Mock Network
    mock_net = mocker.Mock()
    mock_net.name = "default"
    mock_net_client.return_value.list.return_value = [mock_net]

    # Mock Subnet Aggregated List
    mock_subnet = mocker.Mock()
    mock_subnet.name = "default"
    mock_subnet.network = "global/networks/default"
    mock_subnet.ip_cidr_range = "10.128.0.0/20"
    mock_subnet.private_ip_google_access = True
    mock_subnet.enable_flow_logs = False

    # AggregatedList returns (region, {subnetworks: [...]}) tuples
    mock_subnet_client.return_value.aggregated_list.return_value = [
        ("regions/us-central1", mocker.Mock(subnetworks=[mock_subnet]))
    ]

    # Mock Addresses Aggregated List
    mock_addr = mocker.Mock()
    mock_addr.name = "unused-ip"
    mock_addr.address = "34.1.2.3"
    mock_addr.status = "RESERVED"
    mock_addr.users = []

    mock_addr_client.return_value.aggregated_list.return_value = [
        ("regions/us-west1", mocker.Mock(addresses=[mock_addr]))
    ]

    # Call function
    report = get_network_report(project_id="test-project")

    # Assertions
    assert len(report.firewalls) == 1
    fw = report.firewalls[0]
    assert fw.name == "default-allow-ssh"
    assert "0.0.0.0/0" in fw.source_ranges
    assert fw.action == "ALLOW"

    assert len(report.vpcs) == 1
    vpc = report.vpcs[0]
    assert vpc.name == "default"
    assert len(vpc.subnets) == 1
    assert vpc.subnets[0].cidr_range == "10.128.0.0/20"

    assert len(report.addresses) == 1
    addr = report.addresses[0]
    assert addr.address == "34.1.2.3"
    assert addr.status == "RESERVED"
