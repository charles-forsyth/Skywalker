from datetime import datetime

from pydantic import BaseModel, Field


class GCPDisk(BaseModel):
    name: str
    size_gb: int
    type: str = Field(description="e.g., PERSISTENT, SCRATCH")
    boot: bool


class GCPGpu(BaseModel):
    name: str
    count: int
    type: str = Field(description="e.g., nvidia-tesla-t4")


class GCPComputeInstance(BaseModel):
    name: str
    id: str
    status: str
    machine_type: str = Field(description="Cleaned machine type (e.g., n1-standard-1)")
    zone: str
    creation_timestamp: datetime
    labels: dict[str, str] = Field(default_factory=dict)
    disks: list[GCPDisk] = Field(default_factory=list)
    gpus: list[GCPGpu] = Field(default_factory=list)
    internal_ip: str | None = None
    external_ip: str | None = None


class GCPImage(BaseModel):
    name: str
    id: str
    creation_timestamp: datetime
    disk_size_gb: int
    status: str
    archive_size_bytes: int | None = None


class GCPSnapshot(BaseModel):
    name: str
    id: str
    creation_timestamp: datetime
    disk_size_gb: int
    status: str
    storage_bytes: int


class GCPComputeReport(BaseModel):
    instances: list[GCPComputeInstance] = Field(default_factory=list)
    images: list[GCPImage] = Field(default_factory=list)
    snapshots: list[GCPSnapshot] = Field(default_factory=list)