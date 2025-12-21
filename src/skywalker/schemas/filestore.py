from datetime import datetime

from pydantic import BaseModel, Field


class GCPFilestoreInstance(BaseModel):
    name: str
    tier: str
    state: str
    capacity_gb: int
    ip_addresses: list[str] = Field(default_factory=list)
    create_time: datetime | None = None
    location: str
