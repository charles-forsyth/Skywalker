from google.cloud import run_v2
from tenacity import retry

from ..core import RETRY_CONFIG, memory
from ..schemas.run import GCPCloudRunService


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_services(project_id: str, region: str) -> list[GCPCloudRunService]:
    """
    Lists Cloud Run services in a specific region.
    """
    client = run_v2.ServicesClient()
    parent = f"projects/{project_id}/locations/{region}"

    results = []
    # Note: If the API is not enabled or region is empty, this might throw.
    # We rely on the main loop's exception handler or tenacity for now.

    request = run_v2.ListServicesRequest(parent=parent)

    for service in client.list_services(request=request):
        # Extract container image from the first container in the template
        image = "unknown"
        if service.template.containers:
            image = service.template.containers[0].image

        results.append(
            GCPCloudRunService(
                name=service.name.split("/")[-1],  # projects/.../services/SERVICE_NAME
                region=region,
                url=service.uri,
                image=image,
                create_time=service.create_time,
                last_modifier=service.last_modifier,
                ingress_traffic=str(service.ingress),  # Enum to string
                generation=service.generation,
            )
        )

    return results
