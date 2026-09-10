"""
FastAPI wrapper around the LangGraph agent pipeline.
This is the contract your Backend Developer teammate should build against:
    POST /analyze  {"input": "...", "session_id": "..."}  -> full report JSON
"""
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from pydantic import BaseModel

from app.graph import security_graph

app = FastAPI(title="SecureSphere AI - Agent Service")


class AnalyzeRequest(BaseModel):
    input: str
    session_id: str = "default"


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    initial_state = {
        "session_id": req.session_id,
        "raw_input": req.input,
        "findings": [],
    }
    result = security_graph.invoke(initial_state)
    return result["final_report"]


@app.get("/health")
def health():
    return {"status": "ok"}
