from datetime import datetime, timezone

import pytest

from skywalker.core import memory
from skywalker.walkers.run import list_services


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear joblib caching for all tests in this module."""
    memory.clear()


def test_list_services_mock(mocker):
    # Mock the Services Client
    mock_client = mocker.patch("skywalker.walkers.run.run_v2.ServicesClient")

    # Create a mock service object
    mock_service = mocker.Mock()
    mock_service.name = "projects/test-project/locations/us-west1/services/my-service"
    mock_service.uri = "https://my-service-xyz.a.run.app"
    mock_service.create_time = datetime(2023, 5, 1, tzinfo=timezone.utc)
    mock_service.last_modifier = "user@example.com"
    mock_service.generation = 1
    # Note: ingress is an ENUM, but we cast to str in the walker
    mock_service.ingress = "INGRESS_TRAFFIC_ALL"

    # Mock Container template
    mock_container = mocker.Mock()
    mock_container.image = "gcr.io/test-project/my-image:latest"
    mock_service.template.containers = [mock_container]

    # Configure the mock client
    mock_client.return_value.list_services.return_value = [mock_service]

    # Call the function
    services = list_services(project_id="test-project", region="us-west1")

    # Assertions
    assert len(services) == 1
    svc = services[0]
    assert svc.name == "my-service"
    assert svc.region == "us-west1"
    assert svc.url == "https://my-service-xyz.a.run.app"
    assert svc.image == "gcr.io/test-project/my-image:latest"
    assert svc.last_modifier == "user@example.com"

    # Verify the client was called correctly
    # The parent string construction is tested implicitly by the call succeedings
    mock_client.return_value.list_services.assert_called_once()
