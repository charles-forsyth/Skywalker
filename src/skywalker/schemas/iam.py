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

    @property
    def categorized_members(self) -> dict[str, list[str]]:
        categories: dict[str, list[str]] = {
            "users": [],
            "service_accounts": [],
            "groups": [],
            "domains": [],
            "unknown": [],
        }
        for m in self.members:
            if m.startswith("user:"):
                categories["users"].append(m.split(":")[1])
            elif m.startswith("serviceAccount:"):
                categories["service_accounts"].append(m.split(":")[1])
            elif m.startswith("group:"):
                categories["groups"].append(m.split(":")[1])
            elif m.startswith("domain:"):
                categories["domains"].append(m.split(":")[1])
            else:
                categories["unknown"].append(m)
        return categories


class GCPIAMReport(BaseModel):
    service_accounts: list[GCPServiceAccount] = Field(default_factory=list)
    policy_bindings: list[GCPPolicyBinding] = Field(default_factory=list)
