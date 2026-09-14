from pydantic import BaseModel, ConfigDict
from datetime import datetime


class HistoryItem(BaseModel):
    id: int
    input_type: str
    target: str
    risk: str
    score: int
    reasons: list[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class HistoryResponse(BaseModel):
    total_scans: int
    high_risk_count: int
    campaign_flagged: bool
    campaign_message: str | None
    items: list[HistoryItem]
