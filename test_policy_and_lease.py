import subprocess
import time
import json
import sqlite3
import os
import binascii
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from nacl.signing import SigningKey

print("--- Running TDD Policy and Lease Tests ---")

# Setup Keys
ledger_sk = SigningKey.generate()
ledger_vk_hex = binascii.hexlify(ledger_sk.verify_key.encode()).decode()
device_sk = SigningKey.generate()
device_sk_hex = binascii.hexlify(device_sk.encode()).decode()
device_id = "test-policy-device"

# Globals for Mock Handler
mock_lease_status = 200
mock_lease_body = None
lease_requests = 0

class MockLeaseHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global mock_lease_status, mock_lease_body, lease_requests
        
        if self.path == '/lease':
            lease_requests += 1
            self.send_response(mock_lease_status)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            body = mock_lease_body
            if body is None:
                # Default successful lease
                # Let's create a signature over "LEASE:test-policy-device:<expires_at>"
                expires_at = int(time.time()) + 30
                msg = f"LEASE:{device_id}:{expires_at}".encode()
                sig = binascii.hexlify(ledger_sk.sign(msg).signature).decode()
                body = {
                    "expires_at": expires_at,
                    "lease_signature": sig
                }
            self.wfile.write(json.dumps(body).encode())
            return
            
        elif self.path == '/seal':
            # Just accept background sync seals to prevent noise
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "receipt_signature": "00"*64, "ledger_timestamp": 1234, "chain_hash": "aaa"}).encode())
            return

    def log_message(self, format, *args):
        pass

server = HTTPServer(('127.0.0.1', 8083), MockLeaseHandler)
threading.Thread(target=server.serve_forever, daemon=True).start()

def run_proxy(policy_json, req_payload, env_overrides=None):
    if os.path.exists("daemon/queue.db"):
        os.remove("daemon/queue.db")

    env = os.environ.copy()
    env["ACCOUNTABILITY_PRIVATE_KEY"] = device_sk_hex
    env["ACCOUNTABILITY_DEVICE_ID"] = device_id
    env["LEDGER_PUBLIC_KEY"] = ledger_vk_hex
    env["LEDGER_URL"] = "http://127.0.0.1:8083"
    env["ACCOUNTABILITY_QUEUE_DB_PATH"] = "queue.db"
    env["ACCOUNTABILITY_ENCRYPTION_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    env["ACCOUNTABILITY_POLICY_JSON"] = json.dumps(policy_json)
    if env_overrides:
        env.update(env_overrides)

    proc = subprocess.Popen(
        ["./target/debug/autonomous-agent-accountability", "--", "cat"],
        cwd="daemon", env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    proc.stdin.write(req_payload)
    proc.stdin.flush()
    time.sleep(0.5)

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

    proc.kill()
    return out

# --- TESTS ---

test_policy = {
    "default_mode": "require_ledger",
    "rules": [
        {
            "tool": "read_safe_data",
            "mode": "bypass"
        },
        {
            "tool": "execute_wire_transfer",
            "mode": "bypass_if",
            "bypass_condition": {
                "param": "amount",
                "less_than": 10000
            }
        }
    ]
}

print("\n[Test 1] Unconditional bypass rule (read_safe_data)")
lease_requests = 0
out = run_proxy(test_policy, b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_safe_data"}}\n')
assert b"read_safe_data" in out, "Tool should bypass instantly and execute!"
assert lease_requests == 0, "Lease should not have been requested for bypassed tool!"
print("✅ Test 1 Passed")

print("\n[Test 2] Conditional bypass rule (execute_wire_transfer < 10000)")
lease_requests = 0
out = run_proxy(test_policy, b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_wire_transfer","amount":5000}}\n')
assert b"execute_wire_transfer" in out, "Tool should bypass instantly when amount < 10000!"
assert lease_requests == 0, "Lease should not have been requested for bypassed condition!"
print("✅ Test 2 Passed")

print("\n[Test 3] Conditional require_ledger rule (execute_wire_transfer >= 10000)")
lease_requests = 0
mock_lease_status = 200
out = run_proxy(test_policy, b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_wire_transfer","amount":15000}}\n')
assert b"execute_wire_transfer" in out, "Tool should execute after getting lease!"
assert lease_requests == 1, "Lease MUST be requested when amount >= 10000!"
print("✅ Test 3 Passed")

print("\n[Test 4] Default require_ledger rule (cmd)")
lease_requests = 0
mock_lease_status = 200
out = run_proxy(test_policy, b'{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"cmd"}}\n')
assert b"cmd" in out, "Tool should execute after getting lease!"
assert lease_requests == 1, "Lease MUST be requested for default deny tools!"
print("✅ Test 4 Passed")

print("\n[Test 5] Lease Caching (Two calls within 30s)")
lease_requests = 0
mock_lease_status = 200
def run_proxy_two_calls(policy_json):
    if os.path.exists("daemon/queue.db"): os.remove("daemon/queue.db")
    env = os.environ.copy()
    env["ACCOUNTABILITY_PRIVATE_KEY"] = device_sk_hex
    env["ACCOUNTABILITY_DEVICE_ID"] = device_id
    env["LEDGER_PUBLIC_KEY"] = ledger_vk_hex
    env["LEDGER_URL"] = "http://127.0.0.1:8083"
    env["ACCOUNTABILITY_QUEUE_DB_PATH"] = "queue.db"
    env["ACCOUNTABILITY_ENCRYPTION_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    env["ACCOUNTABILITY_POLICY_JSON"] = json.dumps(policy_json)
    proc = subprocess.Popen(["./target/debug/autonomous-agent-accountability", "--", "cat"], cwd="daemon", env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(b'{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"cmd"}}\n')
    proc.stdin.flush()
    time.sleep(0.5)
    proc.stdin.write(b'{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"cmd"}}\n')
    proc.stdin.flush()
    time.sleep(0.5)
    import fcntl; fl = fcntl.fcntl(proc.stdout, fcntl.F_GETFL); fcntl.fcntl(proc.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    out = b""
    try:
        while True:
            chunk = proc.stdout.read()
            if not chunk: break
            out += chunk
    except Exception: pass
    proc.kill()
    return out

out = run_proxy_two_calls(test_policy)
assert out.count(b"cmd") == 2, "Both tools should execute!"
assert lease_requests == 1, "Lease MUST be cached and only requested once for two quick calls!"
print("✅ Test 5 Passed")

print("\n[Test 6] Rogue Agent Fail-Closed (Revoked/401 Lease)")
lease_requests = 0
mock_lease_status = 401
mock_lease_body = {"error": "Kill-switch engaged. Agent authorization revoked."}
out = run_proxy(test_policy, b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"execute_wire_transfer","amount":50000}}\n')
assert b"execute_wire_transfer" not in out, "Tool MUST NOT execute when lease is revoked!"
assert b"Accountability proxy denied execution" in out, "Proxy must emit an error message!"
assert lease_requests == 1, "Lease must have been requested and rejected!"
print("✅ Test 6 Passed")

print("\n🚀 All TDD Policy & Lease Tests Passed! 🚀")
