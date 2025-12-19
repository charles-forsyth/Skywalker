from google.cloud import resourcemanager_v3
from tenacity import retry

from ..core import RETRY_CONFIG, memory


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_all_projects() -> list[str]:
    """
    Lists all ACTIVE projects that the current user has access to.
    Returns a list of project_id strings.
    """
    client = resourcemanager_v3.ProjectsClient()

    # We don't specify a parent to list all projects the user can see
    # filtering for ACTIVE state.
    request = resourcemanager_v3.SearchProjectsRequest(query="state:ACTIVE")

    projects = []
    for project in client.search_projects(request=request):
        projects.append(project.project_id)

    return sorted(projects)
