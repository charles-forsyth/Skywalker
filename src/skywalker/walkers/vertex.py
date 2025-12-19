from google.cloud import aiplatform, notebooks_v1
from tenacity import retry

from ..core import RETRY_CONFIG, memory
from ..schemas.vertex import (
    GCPVertexEndpoint,
    GCPVertexModel,
    GCPVertexNotebook,
    GCPVertexReport,
)


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def get_vertex_report(project_id: str, location: str) -> GCPVertexReport:
    """
    Scans Vertex AI resources in a specific region.
    """
    report = GCPVertexReport()

    # 1. Notebooks (Workbench Instances)
    # Using Notebooks Client separately because aiplatform SDK focuses on MLOps
    nb_client = notebooks_v1.NotebookServiceClient()
    parent = f"projects/{project_id}/locations/{location}"

    try:
        request = notebooks_v1.ListInstancesRequest(parent=parent)
        for nb in nb_client.list_instances(request=request):
            report.notebooks.append(
                GCPVertexNotebook(
                    name=nb.name.split("/")[-1],
                    # Notebooks don't have separate display names usually
                    display_name=nb.name.split("/")[-1],
                    state=str(nb.state.name),
                    creator=nb.creator,
                    update_time=nb.update_time,
                    location=location,
                )
            )
    except Exception:
        # Region might not support Notebooks or API disabled
        pass

    # Initialize Vertex AI SDK for this location
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
            # count deployed models
            deployed_count = len(ep.traffic_split) if ep.traffic_split else 0

            report.endpoints.append(
                GCPVertexEndpoint(
                    name=ep.resource_name.split("/")[-1],
                    display_name=ep.display_name,
                    deployed_models=deployed_count,
                    location=location,
                )
            )

    except Exception:
        pass

    return report
