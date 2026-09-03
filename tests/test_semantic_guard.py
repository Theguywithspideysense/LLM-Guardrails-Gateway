import json
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
import app.guards.semantic_guard as module
from app.guards.semantic_guard import semantic_check

@pytest.mark.parametrize("payload", [
    "not json", {}, {"safe": "true", "category":"none", "confidence":1.0, "reason":"x"},
    {"safe":False,"category":"none","confidence":1.0,"reason":"x"},
    {"safe":True,"category":"jailbreak","confidence":1.0,"reason":"x"},
    {"safe":False,"category":"invented","confidence":1.0,"reason":"x"},
    {"safe":True,"category":"none","confidence":2.0,"reason":"x"},
    {"safe":True,"category":"none","confidence":float("nan"),"reason":"x"},
    {"safe":True,"category":"none","confidence":True,"reason":"x"},
    {"safe":True,"category":"none","confidence":0.9,"reason":"x","unexpected":True},
])
def test_malformed_verdict_fails_closed(monkeypatch,payload):
    raw=payload if isinstance(payload,str) else json.dumps(payload)
    client=Mock()
    client.chat.return_value=SimpleNamespace(message=SimpleNamespace(content=raw))
    monkeypatch.setattr(module,"client",client)
    result=semantic_check("Normal question")
    assert result["error"] and result["blocked"]


def test_classifier_receives_masked_input_and_shared_config(monkeypatch):
    client=Mock()
    client.chat.return_value=SimpleNamespace(message=SimpleNamespace(content=json.dumps(
        {"safe":True,"category":"none","confidence":0.9,"reason":"ordinary request"})))
    monkeypatch.setattr(module,"client",client)
    result=semantic_check("Contact demo@example.com")
    assert not result["blocked"]
    kwargs=client.chat.call_args.kwargs
    assert kwargs["model"] == module.settings.model
    assert "demo@example.com" not in kwargs["messages"][1]["content"]
    assert isinstance(kwargs["format"],dict)


def test_connection_error_fails_closed_without_provider_details(monkeypatch):
    client=Mock()
    client.chat.side_effect=ConnectionError("sensitive provider diagnostics")
    monkeypatch.setattr(module,"client",client)
    result=semantic_check("Normal question")
    assert result["blocked"] and result["error"]
    assert "sensitive provider diagnostics" not in str(result)
