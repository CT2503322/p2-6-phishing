import json

import os

from fastapi.testclient import TestClient

import backend.api.index as api_index


def _install_llm_stubs(monkeypatch, call_counter):
    def fake_call(client, model, prompt):
        call_counter["count"] += 1
        return json.dumps(
            {
                "probability": 90,
                "indicators": ["Urgent request", "Suspicious link"],
                "reasoning": "Indicators resemble phishing patterns",
            }
        )

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(api_index, "OpenAI", lambda api_key: object())
    monkeypatch.setattr(api_index, "_call_llm_model", fake_call)


def test_llm_caching_reuses_previous_results(monkeypatch):
    api_index._LLM_CACHE.clear()
    call_counter = {"count": 0}
    _install_llm_stubs(monkeypatch, call_counter)

    client = TestClient(api_index.app)

    parsed_payload = {
        "from": "alerts@example.com",
        "subject": "Urgent billing update",
        "body": "Please verify your account immediately",
    }

    payload = {"parsed": parsed_payload, "model": "gpt-5-nano"}

    first = client.post("/analyze/llm", json=payload)
    assert first.status_code == 200

    second = client.post("/analyze/llm", json=payload)
    assert second.status_code == 200

    assert call_counter["count"] == 1
    assert first.json() == second.json()


def test_llm_batch_uses_cache_for_duplicate_items(monkeypatch):
    api_index._LLM_CACHE.clear()
    call_counter = {"count": 0}
    _install_llm_stubs(monkeypatch, call_counter)

    client = TestClient(api_index.app)

    parsed_payload = {
        "from": "alerts@example.com",
        "subject": "Urgent billing update",
        "body": "Please verify your account immediately",
    }

    batch_request = {
        "items": [
            {"parsed": parsed_payload},
            {"parsed": parsed_payload},
        ]
    }

    response = client.post("/analyze/llm/batch", json=batch_request)
    assert response.status_code == 200

    results = response.json()["results"]
    assert len(results) == 2
    assert results[0] == results[1]
    assert call_counter["count"] == 1
