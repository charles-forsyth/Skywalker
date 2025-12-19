from datetime import datetime, timezone

import pytest

from skywalker.core import memory
from skywalker.walkers.vertex import get_vertex_report


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear joblib caching for all tests in this module."""
    memory.clear()


def test_get_vertex_report_mock(mocker):
    # Mock Notebooks Client
    mock_nb_client = mocker.patch(
        "skywalker.walkers.vertex.notebooks_v1.NotebookServiceClient"
    )

    # Mock Notebook instance
    mock_nb = mocker.Mock()
    mock_nb.name = "projects/test/locations/us-west1/instances/test-notebook"
    mock_nb.state.name = "ACTIVE"
    mock_nb.creator = "user@example.com"
    mock_nb.update_time = datetime(2023, 1, 1, tzinfo=timezone.utc)

    mock_nb_client.return_value.list_instances.return_value = [mock_nb]

    # Mock AI Platform init and Model/Endpoint
    mock_init = mocker.patch("skywalker.walkers.vertex.aiplatform.init")
    mock_model_cls = mocker.patch("skywalker.walkers.vertex.aiplatform.Model")
    mock_endpoint_cls = mocker.patch("skywalker.walkers.vertex.aiplatform.Endpoint")

    # Mock Model
    mock_model = mocker.Mock()
    mock_model.resource_name = "projects/test/locations/us-west1/models/model-1"
    mock_model.display_name = "My Model"
    mock_model.create_time = datetime(2023, 2, 1, tzinfo=timezone.utc)
    mock_model.version_id = "1"
    mock_model_cls.list.return_value = [mock_model]

    # Mock Endpoint
    mock_ep = mocker.Mock()
    mock_ep.resource_name = "projects/test/locations/us-west1/endpoints/ep-1"
    mock_ep.display_name = "My Endpoint"
    mock_ep.traffic_split = {"d": 100}  # count = 1
    mock_endpoint_cls.list.return_value = [mock_ep]

    # Call function
    report = get_vertex_report(project_id="test-project", location="us-west1")

    # Assertions
    assert len(report.notebooks) == 1
    assert report.notebooks[0].name == "test-notebook"
    assert report.notebooks[0].location == "us-west1"

    assert len(report.models) == 1
    assert report.models[0].display_name == "My Model"

    assert len(report.endpoints) == 1
    assert report.endpoints[0].deployed_models == 1

    mock_init.assert_called_with(project="test-project", location="us-west1")
