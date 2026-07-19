import pytest
from fastapi.testclient import TestClient
from main import app, generate_device_signature
import time

client = TestClient(app)

# Test Variables
DEVICE_ID = "dev_macbook_01"
DEVICE_SECRET = "LOCAL_MOCK_SECRET_123"
HACKATHON_ACCOUNTABILITY_SECRET = "HACKATHON_ACCOUNTABILITY_SECRET_2026"

def test_seal_valid_request():
    payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    local_timestamp = int(time.time())
    
    # Daemon generates the signature locally
    device_sig = generate_device_signature(payload_hash, local_timestamp, DEVICE_ID, DEVICE_SECRET)
    
    req_body = {
        "payload_hash": payload_hash,
        "agent_id": "openai/gpt-5.6-codex",
        "local_timestamp": local_timestamp,
        "device_id": DEVICE_ID,
        "device_signature": device_sig
    }
    
    response = client.post("/seal", json=req_body)
    assert response.status_code == 200
    data = response.json()
    
    assert data["status"] == "sealed"
    assert "receipt_signature" in data
    assert "ledger_timestamp" in data

def test_seal_invalid_device_signature():
    req_body = {
        "payload_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "agent_id": "openai/gpt-5.6-codex",
        "local_timestamp": int(time.time()),
        "device_id": DEVICE_ID,
        "device_signature": "fake_or_tampered_signature"
    }
    
    response = client.post("/seal", json=req_body)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid device signature"

def test_seal_missing_payload_hash():
    req_body = {
        "agent_id": "openai/gpt-5.6-codex",
        "local_timestamp": int(time.time()),
        "device_id": DEVICE_ID,
        "device_signature": "doesnt_matter"
    }
    
    response = client.post("/seal", json=req_body)
    assert response.status_code == 422
