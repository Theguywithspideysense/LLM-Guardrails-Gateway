from dataclasses import replace
from unittest.mock import Mock
import pytest
from fastapi.testclient import TestClient
import app.main as main
import app.guards.semantic_guard as semantic
import app.services.event_store as events
import app.services.gateway as pipeline
from app.config import settings

@pytest.fixture
def gateway_client(monkeypatch, tmp_path):
    config = replace(settings, log_dir=tmp_path / "logs", semantic_enabled=True,
                     admin_key="test-only-admin-key")
    monkeypatch.setattr(main, "settings", config)
    monkeypatch.setattr(pipeline, "settings", config)
    monkeypatch.setattr(semantic, "settings", config)
    monkeypatch.setattr(events, "settings", config)
    monkeypatch.setattr(events, "_handlers", {})
    monkeypatch.setattr(main, "gateway", pipeline.Gateway())
    main.limiter.reset()
    classifier = Mock(return_value={"blocked": False, "reason": None,
                                   "category": "none", "confidence": 0.99, "error": False})
    generate = Mock(return_value="Here is a safe Python explanation.")
    monkeypatch.setattr(pipeline, "semantic_check", classifier)
    monkeypatch.setattr(pipeline, "generate_response", generate)
    monkeypatch.setattr(main, "get_ollama_status", lambda: {
        "ollama": "available", "model_available": True})
    with TestClient(main.app) as client:
        yield client, main.gateway, classifier, generate, config
    for handler in events._handlers.values():
        handler.close()

