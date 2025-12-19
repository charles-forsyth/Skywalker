from pydantic import BaseModel, Field


class GCPFirewallRule(BaseModel):
    name: str
    network: str
    direction: str
    priority: int
    action: str = Field(description="ALLOW or DENY")
    source_ranges: list[str] = Field(default_factory=list)
    allowed_ports: list[str] = Field(default_factory=list)
    target_tags: list[str] = Field(default_factory=list)


class GCPSubnet(BaseModel):
    name: str
    region: str
    cidr_range: str
    private_google_access: bool
    flow_logs: bool


class GCPVPC(BaseModel):
    name: str
    subnets: list[GCPSubnet] = Field(default_factory=list)


class GCPAddress(BaseModel):
    name: str
    address: str
    region: str
    status: str = Field(description="IN_USE or RESERVED")
    user: str | None = None


class GCPNetworkReport(BaseModel):
    firewalls: list[GCPFirewallRule] = Field(default_factory=list)
    vpcs: list[GCPVPC] = Field(default_factory=list)
    addresses: list[GCPAddress] = Field(default_factory=list)
