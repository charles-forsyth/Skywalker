from google.cloud import run_v2
from tenacity import retry

from ..clients import get_run_client
from ..core import RETRY_CONFIG
from ..logger import logger
from ..schemas.run import GCPCloudRunService


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_services(project_id: str, region: str) -> list[GCPCloudRunService]:
    """
    Lists Cloud Run services in a specific region.
    """
    client = get_run_client()
    parent = f"projects/{project_id}/locations/{region}"

    results = []
    try:
        request = run_v2.ListServicesRequest(parent=parent)

        for service in client.list_services(request=request):
            # Extract container image from the first container in the template
            image = "unknown"
            if service.template.containers:
                image = service.template.containers[0].image

            results.append(
                GCPCloudRunService(
                    name=service.name.split("/")[-1],
                    region=region,
                    url=service.uri,
                    image=image,
                    create_time=service.create_time,
                    last_modifier=service.last_modifier,
                    ingress_traffic=str(service.ingress),
                    generation=service.generation,
                )
            )
    except Exception as e:
        logger.warning(f"Failed to list Cloud Run services in {region} for {project_id}: {e}")

    return results