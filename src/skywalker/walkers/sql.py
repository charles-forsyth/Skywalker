from googleapiclient import discovery
from tenacity import retry

from ..core import RETRY_CONFIG, memory
from ..schemas.sql import GCPSQLInstance


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_instances(project_id: str) -> list[GCPSQLInstance]:
    """
    Lists all Cloud SQL instances in the project using the SQL Admin API (v1beta4).
    """
    service = discovery.build("sqladmin", "v1beta4", cache_discovery=False)

    # The list method returns a dict
    request = service.instances().list(project=project_id)
    response = request.execute()

    results = []
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

    return results
