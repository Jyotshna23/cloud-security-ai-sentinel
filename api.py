import json
import logging
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from sentinel import (
    get_client,
    load_history,
    build_past_event_index,
    get_cached_embedding,
    embed_text,
    retrieve_similar_events,
    analyze_threat,
)

logger = logging.getLogger("ai-sentinel-api")

app = FastAPI(
    title="Cloud Security AI Sentinel API",
    description="AI threat classification REST API with RAG historical context",
    version="1.0.0",
)


class SecurityEventRequest(BaseModel):
    event: str = Field(..., min_length=1, max_length=200, examples=["Failed login attempt"])
    ip: str = Field(..., min_length=3, max_length=45, examples=["192.168.1.100"])
    details: Dict[str, Any] = Field(default_factory=dict, examples=[{"attempts": 50}])


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
    except Exception:
        # Log the real error on the server, but do not send it to the caller.
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail="Analysis failed. Please try again later.")
