from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any
from sentinel import (
    get_client,
    load_history,
    build_past_event_index,
    get_cached_embedding,
    embed_text,
    retrieve_similar_events,
    analyze_threat,
)
import json

app = FastAPI(
    title="Cloud Security AI Sentinel API",
    description="Real-time AI threat classification REST API with RAG historical context",
    version="1.0.0",
)


class SecurityEventRequest(BaseModel):
    event: str = Field(..., example="Failed login attempt")
    ip: str = Field(..., example="192.168.1.100")
    details: Dict[str, Any] = Field(default_factory=dict, example={"attempts": 50})


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "cloud-security-ai-sentinel"}


@app.post("/analyze")
def analyze_security_event(payload: SecurityEventRequest):
    try:
        client = get_client()
        raw_event = {"event": payload.event, "ip": payload.ip, **payload.details}
        history = load_history()
        past_index = build_past_event_index(history)

        event_vec = get_cached_embedding(raw_event, past_index)
        if event_vec is None:
            event_vec = embed_text(client, json.dumps(raw_event))

        similar_events = retrieve_similar_events(event_vec, past_index)
        analysis = analyze_threat(client, raw_event, similar_events)
        return {"event": raw_event, "similar_past_matches": len(similar_events), **analysis}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
