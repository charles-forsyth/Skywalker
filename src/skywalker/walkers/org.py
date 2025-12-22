from google.cloud import resourcemanager_v3
from tenacity import retry

from ..clients import get_projects_client
from ..core import RETRY_CONFIG
from ..logger import logger


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_all_projects() -> list[str]:
    """
    Lists all ACTIVE projects that the current user has access to.
    Returns a list of project_id strings.
    """
    projects = []
    try:
        client = get_projects_client()

        # We don't specify a parent to list all projects the user can see
        # filtering for ACTIVE state.
        request = resourcemanager_v3.SearchProjectsRequest(query="state:ACTIVE")

        for project in client.search_projects(request=request):
            projects.append(project.project_id)
    except Exception as e:
        logger.error(f"Failed to discover projects: {e}")

    return sorted(projects)