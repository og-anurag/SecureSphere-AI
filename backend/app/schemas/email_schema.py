from pydantic import BaseModel


class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str

class EmailResponse(BaseModel):
    risk: str
    score: int
    reasons: list[str]
    features: dict    