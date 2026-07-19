import json
import time
import uuid
import binascii
import os
import subprocess
import pytest
from playwright.sync_api import Page, expect
from nacl.signing import SigningKey

# We use session scope to start the local FastAPI server once before tests
@pytest.fixture(scope="session", autouse=True)
def local_ledger_server():
    print("\n[QA Setup] Generating ephemeral keys for test server...")
    # Generate ephemeral keys
    ledger_sk = SigningKey.generate()
    ledger_sk_hex = binascii.hexlify(ledger_sk.encode()).decode()

    device_sk = SigningKey.generate()
    device_sk_hex = binascii.hexlify(device_sk.encode()).decode()
    device_vk_hex = binascii.hexlify(device_sk.verify_key.encode()).decode()
    device_id = "test-device-01"

    authorized_devices = {device_id: device_vk_hex}

    # Store device_sk to use in tests
    os.environ["QA_TEST_DEVICE_PRIVATE_KEY"] = device_sk_hex

    # Clean DB
    if os.path.exists("ledger/test_ledger.db"):
        os.remove("ledger/test_ledger.db")

    print("[QA Setup] Starting local FastAPI on port 8080...")
    ledger_env = os.environ.copy()
    ledger_env["LEDGER_DB_PATH"] = "test_ledger.db"
    ledger_env["LEDGER_PRIVATE_KEY"] = ledger_sk_hex
    ledger_env["AUTHORIZED_DEVICES_JSON"] = json.dumps(authorized_devices)

    proc = subprocess.Popen(
        ["python3", "-m", "uvicorn", "main:app", "--port", "8080"],
        cwd="ledger",
        env=ledger_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for server to start
    time.sleep(2)
    
    yield
    
    print("\n[QA Teardown] Terminating local FastAPI...")
    proc.terminate()


def test_manual_qa_swagger_flow(page: Page):
    print("\n[QA Test] Navigating to Local Swagger UI...")
    page.goto("http://localhost:8080/docs")

    print("[QA Test] Expanding POST /seal endpoint...")
    page.locator("text=POST/seal").click()

    print("[QA Test] Clicking 'Try it out'...")
    page.locator("button:has-text('Try it out')").click()

    # Ephemeral key from setup
    private_key_hex = os.environ["QA_TEST_DEVICE_PRIVATE_KEY"]
    signing_key = SigningKey(binascii.unhexlify(private_key_hex))

    payload_hash = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
    local_timestamp = int(time.time())
    device_id = "test-device-01"
    nonce = str(uuid.uuid4())
    agent_id = "manual_qa_bot"

    # Cryptographic binding
    message = f"{payload_hash}:{local_timestamp}:{device_id}:{nonce}:{agent_id}".encode('utf-8')
    device_sig = binascii.hexlify(signing_key.sign(message).signature).decode('utf-8')

    mock_json = {
      "payload_hash": payload_hash,
      "agent_id": agent_id,
      "local_timestamp": local_timestamp,
      "nonce": nonce,
      "device_id": device_id,
      "device_signature": device_sig
    }

    print("[QA Test] Entering JSON payload...")
    page.locator("textarea.body-param__text").fill(json.dumps(mock_json, indent=2))

    print("[QA Test] Clicking Execute...")
    page.locator("button.execute").click()

    print("[QA Test] Waiting for server response...")
    server_response_table = page.locator("h4:has-text('Server response') + table")
    expect(server_response_table).to_be_visible(timeout=10000)

    print("[QA Test] Validating JSON response payload...")
    expect(server_response_table).to_contain_text("200")
    expect(server_response_table).to_contain_text("receipt_signature")
    
    print("[QA Test] ✅ SUCCESS: Manual QA Playwright Test Passed!")


def test_manual_qa_invalid_signature_flow(page: Page):
    print("\n[QA Test] Testing 401 Unauthorized Flow...")
    page.goto("http://localhost:8080/docs")
    page.locator("text=POST/seal").click()
    page.locator("button:has-text('Try it out')").click()

    invalid_json = {
      "payload_hash": "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2",
      "agent_id": "hacker_bot",
      "local_timestamp": int(time.time()),
      "nonce": str(uuid.uuid4()),
      "device_id": "test-device-01",
      "device_signature": "00" * 64  # Invalid 64-byte hex signature
    }

    page.locator("textarea.body-param__text").fill(json.dumps(invalid_json, indent=2))
    page.locator("button.execute").click()

    server_response_table = page.locator("h4:has-text('Server response') + table")
    expect(server_response_table).to_be_visible(timeout=10000)

    expect(server_response_table).to_contain_text("401")
    expect(server_response_table).to_contain_text("Invalid device signature")
    
    print("[QA Test] ✅ SUCCESS: Security Block 401 Verified!")
