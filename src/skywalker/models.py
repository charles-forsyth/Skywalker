from datetime import datetime

from pydantic import BaseModel, Field


class GCPComputeInstance(BaseModel):
    name: str
    id: str
    status: str
    machine_type: str = Field(description="Cleaned machine type (e.g., n1-standard-1)")
    zone: str
    creation_timestamp: datetime
    labels: dict[str, str] = Field(default_factory=dict)
