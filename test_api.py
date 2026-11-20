import sys, types
from fastapi.testclient import TestClient

# Stub the sentinel module so the test needs no Gemini key
stub = types.ModuleType("sentinel")
stub.get_client = lambda: object()
stub.load_history = lambda: []
stub.build_past_event_index = lambda h: []
stub.get_cached_embedding = lambda e, i: None
stub.embed_text = lambda c, t: [0.1, 0.2]
stub.retrieve_similar_events = lambda v, i: []
stub.analyze_threat = lambda c, e, s: {"threat_level": "HIGH", "score": 80}
sys.modules["sentinel"] = stub

import api
client = TestClient(api.app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "healthy"


def test_analyze_ok():
    r = client.post("/analyze", json={"event": "Failed login", "ip": "10.0.0.1"})
    assert r.status_code == 200 and r.json()["threat_level"] == "HIGH"


def test_analyze_rejects_empty_event():
    r = client.post("/analyze", json={"event": "", "ip": "10.0.0.1"})
    assert r.status_code == 422


def test_analyze_hides_internal_error(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret internal detail")
    monkeypatch.setattr(api, "analyze_threat", boom)
    r = client.post("/analyze", json={"event": "x", "ip": "10.0.0.1"})
    assert r.status_code == 500
    assert "secret" not in r.text
