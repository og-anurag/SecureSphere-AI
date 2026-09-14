from pydantic import BaseModel


class PaymentRequest(BaseModel):
    upi_id: str


class PaymentResponse(BaseModel):
    upi_id: str
    risk: str
    score: int
    reasons: list[str]
    features: dict
