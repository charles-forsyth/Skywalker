from pydantic import BaseModel, Field


class GCPNodePool(BaseModel):
    name: str
    machine_type: str
    disk_size_gb: int
    node_count: int
    version: str
    status: str


class GCPCluster(BaseModel):
    name: str
    location: str
    status: str
    version: str
    endpoint: str
    node_pools: list[GCPNodePool] = Field(default_factory=list)
    network: str
    subnetwork: str
