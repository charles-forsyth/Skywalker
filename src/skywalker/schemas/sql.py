from pydantic import BaseModel


class GCPSQLInstance(BaseModel):
    name: str
    region: str
    database_version: str
    tier: str
    status: str
    public_ip: str | None = None
    private_ip: str | None = None
    storage_limit_gb: int
    storage_usage_bytes: int | None = None
