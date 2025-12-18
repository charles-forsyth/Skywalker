from datetime import datetime

from pydantic import BaseModel


class GCPCloudRunService(BaseModel):
    name: str
    region: str
    url: str
    image: str
    create_time: datetime
    last_modifier: str
    ingress_traffic: str
    # Security audit field: verification if unauthenticated access is allowed
    # (This usually requires checking IAM policies, but we'll start with basic config)
    generation: int
