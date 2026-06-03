from pydantic import BaseModel


class GCPAPIKey(BaseModel):
    name: str
    uid: str
    display_name: str
    created_at: str
    restrictions: dict[str, list[str]] = {}
    is_restricted: bool = False
    masked_key: str | None = None


class GCPAPIKeyUsage(BaseModel):
    service: str
    request_count: int
    estimated_cost: float


class GCPProjectAPIKeysReport(BaseModel):
    project_id: str
    keys: list[GCPAPIKey] = []
    usages: dict[str, list[GCPAPIKeyUsage]] = {}
    total_requests: int = 0
    total_estimated_cost: float = 0.0
