from datetime import datetime

from pydantic import BaseModel, Field


class GCPVertexNotebook(BaseModel):
    name: str
    display_name: str
    state: str
    creator: str
    update_time: datetime
    location: str


class GCPVertexModel(BaseModel):
    name: str
    display_name: str
    create_time: datetime
    version_id: str
    location: str


class GCPVertexEndpoint(BaseModel):
    name: str
    display_name: str
    deployed_models: int
    location: str


class GCPVertexReport(BaseModel):
    notebooks: list[GCPVertexNotebook] = Field(default_factory=list)
    models: list[GCPVertexModel] = Field(default_factory=list)
    endpoints: list[GCPVertexEndpoint] = Field(default_factory=list)
