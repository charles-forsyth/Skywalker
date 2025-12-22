
from skywalker.walkers.vertex import get_vertex_report


def test_get_vertex_report_mock(mocker):
    # Mock Clients
    mock_get_nb = mocker.patch("skywalker.walkers.vertex.get_notebook_client")
    mock_nb = mock_get_nb.return_value

    # Mock aiplatform (high level SDK is harder to mock, so we mock the list methods)
    mock_model_list = mocker.patch("google.cloud.aiplatform.Model.list")
    mock_ep_list = mocker.patch("google.cloud.aiplatform.Endpoint.list")
    mocker.patch("google.cloud.aiplatform.init")

    # Setup Notebooks
    mock_notebook = mocker.Mock()
    mock_notebook.name = "projects/p/locations/u/instances/nb1"
    mock_notebook.state.name = "ACTIVE"
    mock_notebook.creator = "user@example.com"
    mock_notebook.update_time = "2023-01-01"
    mock_nb.list_instances.return_value = [mock_notebook]

    # Setup Models
    mock_model = mocker.Mock()
    mock_model.resource_name = "projects/p/locations/u/models/m1"
    mock_model.display_name = "Model 1"
    mock_model.create_time = "2023-01-01"
    mock_model.version_id = "1"
    mock_model_list.return_value = [mock_model]

    # Setup Endpoints
    mock_ep = mocker.Mock()
    mock_ep.resource_name = "projects/p/locations/u/endpoints/e1"
    mock_ep.display_name = "EP 1"
    mock_ep.traffic_split = {"model1": 100}
    mock_ep_list.return_value = [mock_ep]

    report = get_vertex_report("test-project", "us-central1")

    assert len(report.notebooks) == 1
    assert report.notebooks[0].name == "nb1"
    assert len(report.models) == 1
    assert len(report.endpoints) == 1
