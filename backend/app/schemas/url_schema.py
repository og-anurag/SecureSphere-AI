from pydantic import BaseModel


class URLRequest(BaseModel):
    url: str


class URLResponse(BaseModel):
    url: str
    score: int
    risk: str
    reasons: list[str]