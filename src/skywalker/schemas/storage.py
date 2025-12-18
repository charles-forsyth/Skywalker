from datetime import datetime

from pydantic import BaseModel, Field


class GCPBucket(BaseModel):
    name: str
    location: str
    storage_class: str
    creation_timestamp: datetime
    public_access_prevention: str = Field(
        description="inherited, enforced, or unspecified"
    )
    versioning_enabled: bool = False
    uniform_bucket_level_access: bool = False
