import pytest

from skywalker.walkers.network import get_network_report


def test_get_network_report_mock(mocker):
    # Mock all getters
    mock_get_fw = mocker.patch("skywalker.walkers.network.get_firewalls_client")
    mock_fw = mock_get_fw.return_value
    
    mock_get_net = mocker.patch("skywalker.walkers.network.get_networks_client")
    mock_net = mock_get_net.return_value
    
    mock_get_sub = mocker.patch("skywalker.walkers.network.get_subnetworks_client")
    mock_sub = mock_get_sub.return_value
    
    mock_get_addr = mocker.patch("skywalker.walkers.network.get_addresses_client")
    mock_addr = mock_get_addr.return_value

    # Setup Firewalls
    mock_rule = mocker.Mock()
    mock_rule.name = "allow-ssh"
    mock_rule.network = "global/networks/default"
    mock_rule.direction = "INGRESS"
    mock_rule.allowed = [mocker.Mock(I_p_protocol="tcp", ports=["22"])]
    mock_rule.denied = []
    mock_rule.source_ranges = ["0.0.0.0/0"]
    mock_rule.priority = 1000
    mock_rule.target_tags = []
    mock_fw.list.return_value = [mock_rule]

    # Setup Networks
    mock_vpc = mocker.Mock()
    mock_vpc.name = "default"
    mock_net.list.return_value = [mock_vpc]

    # Setup Subnets
    mock_sn = mocker.Mock()
    mock_sn.name = "default-sn"
    mock_sn.network = "global/networks/default"
    mock_sn.ip_cidr_range = "10.0.0.0/24"
    mock_sn.private_ip_google_access = True
    mock_sn.enable_flow_logs = False
    mock_sub.aggregated_list.return_value = [
        ("regions/us-west1", mocker.Mock(subnetworks=[mock_sn]))
    ]
    
    # Setup Addresses
    mock_addr.aggregated_list.return_value = []

    report = get_network_report("test-project")

    assert len(report.firewalls) == 1
    assert report.firewalls[0].name == "allow-ssh"
    assert len(report.vpcs) == 1
    assert len(report.vpcs[0].subnets) == 1