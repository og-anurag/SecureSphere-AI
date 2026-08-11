from pydantic import BaseModel


class APKResponse(BaseModel):
    filename: str
    file_size: int
    risk: str
    score: int
    reasons: list[str]
    features: dict