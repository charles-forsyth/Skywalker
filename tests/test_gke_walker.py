import pytest

from skywalker.walkers.gke import list_clusters


def test_list_clusters_mock(mocker):
    # Mock the Client Getter
    mock_get = mocker.patch("skywalker.walkers.gke.get_gke_client")
    mock_client = mock_get.return_value

    # Create a mock cluster object
    mock_cluster = mocker.Mock()
    mock_cluster.name = "test-cluster"
    mock_cluster.location = "us-west1"
    mock_cluster.status.name = "RUNNING"
    mock_cluster.current_master_version = "1.27.3-gke.100"
    mock_cluster.endpoint = "1.2.3.4"
    mock_cluster.network = "default"
    mock_cluster.subnetwork = "default"

    # Mock Node Pool
    mock_np = mocker.Mock()
    mock_np.name = "default-pool"
    mock_np.config.machine_type = "e2-medium"
    mock_np.config.disk_size_gb = 100
    mock_np.initial_node_count = 3
    mock_np.version = "1.27.3-gke.100"
    mock_np.status.name = "RUNNING"
    mock_cluster.node_pools = [mock_np]

    # Configure the mock client
    mock_client.list_clusters.return_value = mocker.Mock(clusters=[mock_cluster])

    # Call the function
    clusters = list_clusters(project_id="test-project", location="us-west1")

    # Assertions
    assert len(clusters) == 1
    c = clusters[0]
    assert c.name == "test-cluster"
    assert len(c.node_pools) == 1
    assert c.node_pools[0].node_count == 3

    mock_client.list_clusters.assert_called_once()
