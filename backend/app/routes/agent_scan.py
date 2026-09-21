from fastapi import APIRouter
from pydantic import BaseModel

from agents.app.graph import security_graph


router = APIRouter()


class AgentScanRequest(BaseModel):
    input: str
    session_id: str = "default"


@router.post("/analyze")
def analyze(request: AgentScanRequest):
    initial_state = {
        "session_id": request.session_id,
        "raw_input": request.input,
        "findings": [],
    }

    result = security_graph.invoke(initial_state)

    return result["final_report"]