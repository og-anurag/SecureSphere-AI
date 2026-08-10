from pydantic import BaseModel, HttpUrl


class URLRequest(BaseModel):
    url: HttpUrl


class URLResponse(BaseModel):
    url: str
    score: int
    risk: str
    reasons: list[str]
    features: dict