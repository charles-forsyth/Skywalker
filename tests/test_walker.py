import pytest

from skywalker.walker import list_instances, memory


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear joblib caching for all tests in this module."""
    memory.clear()


def test_list_instances_mock(mocker):
    # Mock the InstancesClient
    mock_client = mocker.patch("skywalker.walker.compute_v1.InstancesClient")

    # Create a mock instance object
    mock_instance = mocker.Mock()
    mock_instance.name = "test-instance"
    mock_instance.id = 12345
    mock_instance.status = "RUNNING"
    mock_instance.machine_type = "zones/us-west1-b/machineTypes/n1-standard-1"
    mock_instance.creation_timestamp = "2023-01-01T12:00:00.000-07:00"
    mock_instance.labels = {"env": "prod"}

    # Configure the mock client to return the mock instance
    mock_client.return_value.list.return_value = [mock_instance]

    # Call the function
    instances = list_instances(project_id="test-project", zone="us-west1-b")

    # Assertions
    assert len(instances) == 1
    assert instances[0].name == "test-instance"
    assert instances[0].machine_type == "n1-standard-1"
    assert instances[0].status == "RUNNING"
    assert instances[0].labels == {"env": "prod"}

    # Verify the client was called correctly
    mock_client.return_value.list.assert_called_once()
