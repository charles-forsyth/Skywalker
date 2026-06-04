from pydantic import BaseModel, Field


class GCPModelUsage(BaseModel):
    model_id: str
    publisher: str
    request_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost: float = 0.0


class GCPProjectModelUsageReport(BaseModel):
    project_id: str
    usages: list[GCPModelUsage] = Field(default_factory=list)
    total_requests: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_estimated_cost: float = 0.0
