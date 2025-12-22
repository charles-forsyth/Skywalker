
from skywalker.walkers.run import list_services


def test_list_run_services_mock(mocker):
    # Mock Getter
    mock_get = mocker.patch("skywalker.walkers.run.get_run_client")
    mock_client = mock_get.return_value

    mock_svc = mocker.Mock()
    mock_svc.name = "projects/p/locations/u/services/mysvc"
    mock_svc.uri = "https://mysvc.a.run.app"
    mock_svc.create_time = "2023-01-01"
    mock_svc.last_modifier = "admin"
    mock_svc.ingress = "INGRESS_TRAFFIC_ALL"
    mock_svc.generation = 1
    mock_svc.template.containers = [mocker.Mock(image="gcr.io/myimg")]

    mock_client.list_services.return_value = [mock_svc]

    results = list_services("test-proj", "us-west1")
    assert len(results) == 1
    assert results[0].name == "mysvc"
    assert results[0].image == "gcr.io/myimg"
