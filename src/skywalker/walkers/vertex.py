from google.cloud import aiplatform
from tenacity import retry

from ..clients import get_notebook_client
from ..core import RETRY_CONFIG
from ..logger import logger
from ..schemas.vertex import (
    GCPVertexEndpoint,
    GCPVertexModel,
    GCPVertexNotebook,
    GCPVertexReport,
)


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def get_vertex_report(project_id: str, location: str) -> GCPVertexReport:
    """
    Scans Vertex AI resources in a specific region.
    """
    report = GCPVertexReport()

    # 1. Notebooks (Workbench Instances)
    nb_client = get_notebook_client()
    parent = f"projects/{project_id}/locations/{location}"

    try:
        from google.cloud import notebooks_v1
        request = notebooks_v1.ListInstancesRequest(parent=parent)
        for nb in nb_client.list_instances(request=request):
            report.notebooks.append(
                GCPVertexNotebook(
                    name=nb.name.split("/")[-1],
                    display_name=nb.name.split("/")[-1],
                    state=str(nb.state.name),
                    creator=nb.creator,
                    update_time=nb.update_time,
                    location=location,
                )
            )
    except Exception as e:
        logger.debug(f"Failed to list Vertex Notebooks in {location} for {project_id}: {e}")

    # Initialize Vertex AI SDK for this location (Models/Endpoints)
    try:
        aiplatform.init(project=project_id, location=location)

        # 2. Models
        for model in aiplatform.Model.list():
            report.models.append(
                GCPVertexModel(
                    name=model.resource_name.split("/")[-1],
                    display_name=model.display_name,
                    create_time=model.create_time,
                    version_id=model.version_id,
                    location=location,
                )
            )

        # 3. Endpoints
        for ep in aiplatform.Endpoint.list():
            deployed_count = len(ep.traffic_split) if ep.traffic_split else 0
            report.endpoints.append(
                GCPVertexEndpoint(
                    name=ep.resource_name.split("/")[-1],
                    display_name=ep.display_name,
                    deployed_models=deployed_count,
                    location=location,
                )
            )

    except Exception as e:
        logger.debug(f"Vertex AI API not enabled or failed in {location} for {project_id}: {e}")

    return report