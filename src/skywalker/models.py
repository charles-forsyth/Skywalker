from typing import Dict
from pydantic import BaseModel, Field
from datetime import datetime

class GCPComputeInstance(BaseModel):
    name: str
    id: str
    status: str
    machine_type: str = Field(description="Cleaned machine type (e.g., n1-standard-1)")
    zone: str
    creation_timestamp: datetime
    labels: Dict[str, str] = Field(default_factory=dict)
