from pydantic import BaseModel
from typing import Optional


class QRResponse(BaseModel):
    risk: str
    score: int
    reasons: list[str]
    features: dict
    decoded_content: Optional[str] = None
