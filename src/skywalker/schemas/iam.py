from datetime import datetime

from pydantic import BaseModel, Field


class GCPKey(BaseModel):
    name: str
    key_type: str = Field(description="USER_MANAGED or SYSTEM_MANAGED")
    valid_after: datetime
    valid_before: datetime


class GCPServiceAccount(BaseModel):
    email: str
    unique_id: str
    display_name: str
    description: str
    disabled: bool
    keys: list[GCPKey] = Field(default_factory=list)


class GCPPolicyBinding(BaseModel):
    role: str
    members: list[str]


class GCPIAMReport(BaseModel):
    service_accounts: list[GCPServiceAccount] = Field(default_factory=list)
    policy_bindings: list[GCPPolicyBinding] = Field(default_factory=list)
