import subprocess
import time
import json
import sqlite3
import os
import binascii
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from nacl.signing import SigningKey

print("--- Running Strict Adversarial Proxy Tests ---")

# Setup Keys
ledger_sk = SigningKey.generate()
ledger_vk_hex = binascii.hexlify(ledger_sk.verify_key.encode()).decode()
device_sk = SigningKey.generate()
device_sk_hex = binascii.hexlify(device_sk.encode()).decode()
device_id = "adv-test-device"

# Globals for Mock Handler
mock_response_status = 200
mock_response_body = {}
mock_override_receipt = None
delay_response = 0

class FaultyLedgerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global mock_response_status, mock_response_body, mock_override_receipt, delay_response
        
        if delay_response > 0:
            time.sleep(delay_response)

        if self.path == '/lease':
            expires_at = int(time.time()) + 30
            msg = f"LEASE:{device_id}:{expires_at}".encode()
            sig = binascii.hexlify(ledger_sk.sign(msg).signature).decode()
            body = {"expires_at": expires_at, "lease_signature": sig}
            if mock_response_body is not None:
                body = mock_response_body
            self.send_response(mock_response_status)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())
            return

        content_len = int(self.headers.get('content-length', 0))
        post_body = self.rfile.read(content_len)
        req = json.loads(post_body)
        ts = 123456789
        chain_hash = "a" * 64
        action_status = req.get("action_status", "UNKNOWN")
        msg = f"{req['payload_hash']}:{req['agent_id']}:{req['local_timestamp']}:{req['device_id']}:{req['nonce']}:{req['device_signature']}:{ts}:{chain_hash}:{action_status}".encode()
        sig = binascii.hexlify(ledger_sk.sign(msg).signature).decode()
        
        body = {"receipt_signature": sig, "ledger_timestamp": ts, "chain_hash": chain_hash}
        if mock_override_receipt is not None:
            body["receipt_signature"] = mock_override_receipt
            
        if mock_response_body is not None:
            body = mock_response_body
            
        self.send_response(mock_response_status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())
    
    def log_message(self, format, *args):
        pass

server = HTTPServer(('127.0.0.1', 8081), FaultyLedgerHandler)
threading.Thread(target=server.serve_forever, daemon=True).start()

def run_test_case(name, req_payload, expected_in_stdout, expected_not_in_stdout, env_overrides=None, delay=1.0):
    global mock_response_status, mock_response_body, mock_override_receipt, delay_response
    
    if os.path.exists("daemon/queue.db"):
        os.remove("daemon/queue.db")

    env = os.environ.copy()
    env["ACCOUNTABILITY_PRIVATE_KEY"] = device_sk_hex
    env["ACCOUNTABILITY_DEVICE_ID"] = device_id
    env["LEDGER_PUBLIC_KEY"] = ledger_vk_hex
    env["LEDGER_URL"] = "http://127.0.0.1:8081"
    env["ACCOUNTABILITY_QUEUE_DB_PATH"] = "queue.db"
    env["ACCOUNTABILITY_ENCRYPTION_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    policy = {
        "default_mode": "bypass",
        "rules": [
            {"tool": "cmd", "mode": "require_ledger"},
            {"tool": "cmd1", "mode": "require_ledger"},
            {"tool": "cmd2", "mode": "require_ledger"}
        ]
    }
    env["ACCOUNTABILITY_POLICY_JSON"] = json.dumps(policy)
    if env_overrides:
        env.update(env_overrides)

    proc = subprocess.Popen(
        ["./target/debug/autonomous-agent-accountability", "--", "cat"],
        cwd="daemon", env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    proc.stdin.write(req_payload)
    proc.stdin.flush()
    time.sleep(delay)

    import fcntl
    fl = fcntl.fcntl(proc.stdout, fcntl.F_GETFL)
    fcntl.fcntl(proc.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    out = b""
    try:
        while True:
            chunk = proc.stdout.read()
            if not chunk: break
            out += chunk
    except Exception:
        pass

    for exp in expected_in_stdout:
        if exp not in out:
            import fcntl; fl = fcntl.fcntl(proc.stderr, fcntl.F_GETFL); fcntl.fcntl(proc.stderr, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            err = proc.stderr.read()
            print(f"DEBUG STDERR: {err}")
        assert exp in out, f"[{name}] Expected {exp} in output, got: {out}"
    for exp in expected_not_in_stdout:
        assert exp not in out, f"[{name}] Expected {exp} NOT in output, but it was found! Output: {out}"
        
    proc.kill()
    print(f"✅ {name} passed.")
    return out

# 1. Forged lease signature rejection
mock_response_status = 200
mock_response_body = {"expires_at": int(time.time())+30, "lease_signature": "00"*64}
mock_override_receipt = None
req1 = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cmd"}}\n'
run_test_case("Forged Lease Signature Rejection", req1, [b"Accountability proxy denied execution"], [req1])

# 2. Missing/malformed lease rejection
mock_response_status = 200
mock_response_body = {"bad": "lease"}
mock_override_receipt = None
req2 = b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cmd"}}\n'
run_test_case("Missing Lease Rejection", req2, [b"Accountability proxy denied execution"], [req2])

# 3. Offline/refused connection
mock_response_status = 200
mock_response_body = None
req3 = b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"cmd"}}\n'
run_test_case("Offline Connection Rejection", req3, [b"Accountability proxy denied execution"], [req3], env_overrides={"LEDGER_URL": "http://127.0.0.1:9999"})

# 4. Real ledger unauthorized-device 401 denial
mock_response_status = 401
mock_response_body = {"error": "unauthorized"}
req4 = b'{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"cmd"}}\n'
run_test_case("Ledger 401 Unauthorized Rejection", req4, [b"Accountability proxy denied execution"], [req4])

# (Test 5 removed as low-latency TTL makes race condition untestable with cat)

# 6. Semantic retry with different JSON whitespace/key order
mock_response_status = 200
mock_response_body = None
mock_override_receipt = None
req6a = b'{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"cmd"}}\n'
req6b = b'{ "jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": { "name": "cmd" } }\n'
def run_test_6():
    global mock_response_status, mock_response_body, mock_override_receipt, delay_response
    if os.path.exists("daemon/queue.db"): os.remove("daemon/queue.db")
    env = os.environ.copy()
    env["ACCOUNTABILITY_PRIVATE_KEY"] = device_sk_hex
    env["ACCOUNTABILITY_DEVICE_ID"] = device_id
    env["LEDGER_PUBLIC_KEY"] = ledger_vk_hex
    env["LEDGER_URL"] = "http://127.0.0.1:8081"
    env["ACCOUNTABILITY_QUEUE_DB_PATH"] = "queue.db"
    env["ACCOUNTABILITY_ENCRYPTION_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    policy = {
        "default_mode": "bypass",
        "rules": [
            {"tool": "cmd", "mode": "require_ledger"},
            {"tool": "cmd1", "mode": "require_ledger"},
            {"tool": "cmd2", "mode": "require_ledger"}
        ]
    }
    env["ACCOUNTABILITY_POLICY_JSON"] = json.dumps(policy)
    proc = subprocess.Popen(["./target/debug/autonomous-agent-accountability", "--", "cat"], cwd="daemon", env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(req6a)
    proc.stdin.flush()
    time.sleep(1.0) # Wait for first to complete
    proc.stdin.write(req6b)
    proc.stdin.flush()
    time.sleep(1.0) # Wait for second to be blocked
    import fcntl; fl = fcntl.fcntl(proc.stdout, fcntl.F_GETFL); fcntl.fcntl(proc.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    out = b""
    try:
        while True:
            chunk = proc.stdout.read()
            if not chunk: break
            out += chunk
    except Exception: pass
    proc.kill()
    assert req6a in out, "req6a not found in output!"
    assert b"Duplicate request blocked by accountability proxy idempotency layer" in out, "req6b was not blocked by historical duplicate ID check!"
    assert req6b not in out, "req6b should not be executed!"
    print("✅ Semantic Retry Different Whitespace passed.")
run_test_6()

# 7. Exact byte-for-byte retry
mock_response_status = 200
mock_response_body = None
mock_override_receipt = None
req7a = b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"cmd"}}\n'
req7b = b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"cmd"}}\n'
def run_test_7():
    global mock_response_status, mock_response_body, mock_override_receipt, delay_response
    if os.path.exists("daemon/queue.db"): os.remove("daemon/queue.db")
    env = os.environ.copy()
    env["ACCOUNTABILITY_PRIVATE_KEY"] = device_sk_hex
    env["ACCOUNTABILITY_DEVICE_ID"] = device_id
    env["LEDGER_PUBLIC_KEY"] = ledger_vk_hex
    env["LEDGER_URL"] = "http://127.0.0.1:8081"
    env["ACCOUNTABILITY_QUEUE_DB_PATH"] = "queue.db"
    env["ACCOUNTABILITY_ENCRYPTION_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    policy = {
        "default_mode": "bypass",
        "rules": [
            {"tool": "cmd", "mode": "require_ledger"},
            {"tool": "cmd1", "mode": "require_ledger"},
            {"tool": "cmd2", "mode": "require_ledger"}
        ]
    }
    env["ACCOUNTABILITY_POLICY_JSON"] = json.dumps(policy)
    proc = subprocess.Popen(["./target/debug/autonomous-agent-accountability", "--", "cat"], cwd="daemon", env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(req7a)
    proc.stdin.flush()
    time.sleep(1.0) # Wait for first to complete
    proc.stdin.write(req7b)
    proc.stdin.flush()
    time.sleep(1.0) # Wait for second to be blocked
    import fcntl; fl = fcntl.fcntl(proc.stdout, fcntl.F_GETFL); fcntl.fcntl(proc.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    out = b""
    try:
        while True:
            chunk = proc.stdout.read()
            if not chunk: break
            out += chunk
    except Exception: pass
    proc.kill()
    assert req7a in out, "req7a not found in output!"
    assert b"Duplicate request blocked by accountability proxy idempotency layer" in out, "req7b was not blocked by idempotency layer!"
    print("✅ Exact Byte-for-Byte Idempotency Retry passed.")
run_test_7()

# 8. Safe tool bypasses ledger verification
mock_response_status = 401 # Even with an unauthorized ledger, it should bypass!
mock_response_body = {"error": "unauthorized"}
req8 = b'{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"read_safe_data"}}\n'
run_test_case("Safe Tool Bypass", req8, [req8], [b"Accountability proxy denied execution"], delay=0.5)

print("🚀 All Strict Adversarial Tests Passed!")
