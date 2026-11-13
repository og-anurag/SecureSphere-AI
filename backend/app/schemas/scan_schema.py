from pydantic import BaseModel, Field
from typing import Any


class ScanFinding(BaseModel):
    agent: str
    signal: str
    detail: str
    severity: str


class ScanResult(BaseModel):
    input_type: str
    target: str

    verdict: str
    risk_score: int = Field(ge=0, le=100)
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)

    findings: list[ScanFinding] = []
    features: dict[str, Any] = {}
    threat_intel: dict[str, Any] = {}

    recommendation: str