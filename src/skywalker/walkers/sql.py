from tenacity import retry

from ..clients import get_sql_client
from ..core import RETRY_CONFIG
from ..logger import logger
from ..schemas.sql import GCPSQLInstance


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_instances(project_id: str) -> list[GCPSQLInstance]:
    """
    Lists all Cloud SQL instances in the project using the SQL Admin API.
    """
    service = get_sql_client()

    results = []
    try:
        request = service.instances().list(project=project_id)
        response = request.execute()

        # response.get("items", []) contains the list of instances (dicts)
        for instance in response.get("items", []):
            public_ip = None
            private_ip = None

            ip_addresses = instance.get("ipAddresses", [])
            for ip in ip_addresses:
                if ip.get("type") == "PRIMARY":
                    public_ip = ip.get("ipAddress")
                elif ip.get("type") == "PRIVATE":
                    private_ip = ip.get("ipAddress")

            settings = instance.get("settings", {})

            results.append(
                GCPSQLInstance(
                    name=instance.get("name"),
                    region=instance.get("region"),
                    database_version=instance.get("databaseVersion"),
                    tier=settings.get("tier"),
                    status=instance.get("state"),
                    public_ip=public_ip,
                    private_ip=private_ip,
                    storage_limit_gb=int(settings.get("dataDiskSizeGb", 0)),
                )
            )
    except Exception as e:
        logger.warning(f"Failed to list SQL instances for {project_id}: {e}")

    return results