from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: StrictStr = Field(min_length=1, description="Prompt to inspect before generation")

    @field_validator("message")
    @classmethod
    def not_blank(cls, value):
        if not value.strip():
            raise ValueError("Message must not be blank")
        return value

class PolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    guardrail: str = Field(min_length=1, max_length=40)
    action: Literal["allow", "block", "warn", "redact"]

class ChatResponse(BaseModel):
    request_id: str
    timestamp: str
    success: bool
    blocked: bool
    action: Literal["allow", "block", "warn", "redact", "error"]
    stage: str
    reason: str
    model: str
    risk: dict
    violation_count: int
    violations: list[dict]
    checks: list[dict]
    redacted: bool
    input_redacted: bool
    output_redacted: bool
    warnings: list[dict]
    prompt_preview: str
    response: str | None
    latency_ms: float
