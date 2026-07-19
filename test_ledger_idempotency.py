import requests
import json
import time
import os
import binascii
from nacl.signing import SigningKey

# 1. Start or Connect to Ledger
LEDGER_URL = "http://localhost:8080"
print(f"Connecting to {LEDGER_URL}")

# Keys
device_sk = SigningKey.generate()
device_vk_hex = binascii.hexlify(device_sk.verify_key.encode()).decode()
device_id = "test-device-id"

# Wait for server to be up
max_retries = 10
for i in range(max_retries):
    try:
        requests.get(LEDGER_URL)
        break
    except requests.ConnectionError:
        time.sleep(1)

# Generate a request
payload_hash = "1" * 64
local_timestamp = int(time.time())
nonce = "123e4567-e89b-12d3-a456-426614174000"
agent_id = "test-agent"
action_status = "AUTHORIZED_DISPATCHED"

message = f"{payload_hash}:{local_timestamp}:{device_id}:{nonce}:{agent_id}:{action_status}".encode('utf-8')
device_signature = binascii.hexlify(device_sk.sign(message).signature).decode()

payload = {
    "payload_hash": payload_hash,
    "agent_id": agent_id,
    "local_timestamp": local_timestamp,
    "nonce": nonce,
    "device_id": device_id,
    "device_signature": device_signature,
    "action_status": action_status
}

# Add device to server via side-channel DB injection or test API (Assume it's added via run_e2e_test.py or we just use the one from there)
# Actually, wait. We need to add this device to AUTHORIZED_DEVICES_JSON.
# In run_e2e_test.py, it passes AUTHORIZED_DEVICES_JSON in env.
# Let's just run this test from run_e2e_test.py directly!
