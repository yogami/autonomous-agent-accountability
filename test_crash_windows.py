import subprocess
import os
import time
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric import ed25519
import binascii

device_sk = ed25519.Ed25519PrivateKey.generate()
device_vk = device_sk.public_key()
device_sk_hex = binascii.hexlify(device_sk.private_bytes_raw()).decode('utf-8')
device_id = "test-device-uuid"

ledger_sk = ed25519.Ed25519PrivateKey.generate()
ledger_vk = ledger_sk.public_key()
ledger_vk_hex = binascii.hexlify(ledger_vk.public_bytes_raw()).decode('utf-8')

ledger_events = []

class MockLedgerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/lease':
            expires_at = int(time.time()) + 30
            msg = f"LEASE:{device_id}:{expires_at}".encode()
            sig = binascii.hexlify(ledger_sk.sign(msg)).decode()
            body = {"expires_at": expires_at, "lease_signature": sig}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())
            return

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        event = json.loads(post_data.decode('utf-8'))
        
        ledger_events.append(event)
        
        # Always return a valid receipt for the crash tests
        receipt_message = f"{event['payload_hash']}:{event['agent_id']}:{event['local_timestamp']}:{event['device_id']}:{event['nonce']}:{event['device_signature']}:1234567890:mock_chain_hash:{event['action_status']}"
        receipt_sig = ledger_sk.sign(receipt_message.encode('utf-8'))
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            "status": "success",
            "receipt_signature": binascii.hexlify(receipt_sig).decode('utf-8'),
            "ledger_timestamp": 1234567890,
            "chain_hash": "mock_chain_hash"
        }).encode('utf-8'))

    def log_message(self, format, *args):
        pass

def start_mock_ledger():
    server = HTTPServer(('127.0.0.1', 8082), MockLedgerHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    return server

def run_test_1():
    global ledger_events
    ledger_events.clear()
    
    if os.path.exists("daemon/queue.db"): os.remove("daemon/queue.db")
    
    env = os.environ.copy()
    env["ACCOUNTABILITY_PRIVATE_KEY"] = device_sk_hex
    env["ACCOUNTABILITY_DEVICE_ID"] = device_id
    env["LEDGER_PUBLIC_KEY"] = ledger_vk_hex
    env["LEDGER_URL"] = "http://127.0.0.1:8082"
    env["ACCOUNTABILITY_QUEUE_DB_PATH"] = "queue.db"
    env["ACCOUNTABILITY_ENCRYPTION_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    env["COUNTER_DB_PATH"] = "../counter.db"
    policy = {
        "default_mode": "bypass",
        "rules": [
            {"tool": "increment_counter", "mode": "require_ledger"},
            {"tool": "cmd", "mode": "require_ledger"}
        ]
    }
    env["ACCOUNTABILITY_POLICY_JSON"] = json.dumps(policy)
    env["CRASH_AFTER_DB_INSERT"] = "1"
    
    print("[Test 1] Spawning proxy, injecting crash after DB insert...")
    proc = subprocess.Popen(["./target/debug/autonomous-agent-accountability", "--", "cat"], cwd="daemon", env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    req = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cmd"}}\n'
    proc.stdin.write(req)
    proc.stdin.flush()
    proc.wait()
    
    assert proc.returncode == 9, "Proxy did not crash as expected!"
    assert len(ledger_events) == 0, "Network dispatch occurred despite crash!"
    
    print("[Test 1] Proxy crashed. Restarting proxy normally...")
    del env["CRASH_AFTER_DB_INSERT"]
    proc2 = subprocess.Popen(["./target/debug/autonomous-agent-accountability", "--", "cat"], cwd="daemon", env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait for background sync
    time.sleep(6)
    proc2.kill()
    
    requested_events = [e for e in ledger_events if e["action_status"] == "SEAL_REQUESTED"]
    assert len(requested_events) == 1, f"Expected 1 SEAL_REQUESTED recovered, found {len(requested_events)}"
    print("✅ Test 1 Passed: Outbox recovered pre-network SEAL_REQUESTED event.")

def run_test_2():
    global ledger_events
    ledger_events.clear()
    
    if os.path.exists("daemon/queue.db"): os.remove("daemon/queue.db")
    
    env = os.environ.copy()
    env["ACCOUNTABILITY_PRIVATE_KEY"] = device_sk_hex
    env["ACCOUNTABILITY_DEVICE_ID"] = device_id
    env["LEDGER_PUBLIC_KEY"] = ledger_vk_hex
    env["LEDGER_URL"] = "http://127.0.0.1:8082"
    env["ACCOUNTABILITY_QUEUE_DB_PATH"] = "queue.db"
    env["ACCOUNTABILITY_ENCRYPTION_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    policy = {
        "default_mode": "bypass",
        "rules": [
            {"tool": "increment_counter", "mode": "require_ledger"},
            {"tool": "cmd", "mode": "require_ledger"}
        ]
    }
    env["ACCOUNTABILITY_POLICY_JSON"] = json.dumps(policy)
    env["CRASH_AFTER_EXECUTION"] = "1"
    
    print("[Test 2] Spawning proxy, injecting crash after tool execution...")
    proc = subprocess.Popen(["./target/debug/autonomous-agent-accountability", "--", "cat"], cwd="daemon", env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    req = b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cmd"}}\n'
    proc.stdin.write(req)
    proc.stdin.flush()
    # Simulate response from tool to trigger SEAL_COMPLETED and the crash
    res = b'{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"Done"}]}}\n'
    proc.stdin.write(res)
    proc.stdin.flush()
    
    proc.wait()
    import fcntl; fl = fcntl.fcntl(proc.stderr, fcntl.F_GETFL); fcntl.fcntl(proc.stderr, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    err_proc = proc.stderr.read()
    if err_proc: print(f"DEBUG STDERR proc:\n{err_proc.decode('utf-8')}")
    assert proc.returncode == 9, "Proxy did not crash as expected!"
    
    import sqlite3
    db = sqlite3.connect("daemon/queue.db")
    c = db.cursor()
    c.execute("SELECT action_status FROM local_audit_log")
    statuses = [row[0] for row in c.fetchall()]
    print(f"DEBUG DB STATUSES AFTER CRASH: {statuses}")
    db.close()

    print("[Test 2] Proxy crashed. Restarting proxy normally...")
    del env["CRASH_AFTER_EXECUTION"]
    proc2 = subprocess.Popen(["./target/debug/autonomous-agent-accountability", "--", "cat"], cwd="daemon", env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(6)
    proc2.kill()

    import fcntl; fl = fcntl.fcntl(proc2.stderr, fcntl.F_GETFL); fcntl.fcntl(proc2.stderr, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    err = proc2.stderr.read()
    if err: print(f"DEBUG STDERR proc2:\n{err.decode('utf-8')}")

    requested_events = [e for e in ledger_events if e["action_status"] == "SEAL_REQUESTED"]
    assert len(requested_events) == 1, "SEAL_REQUESTED was not dispatched!"
    
    completed_events_after_restart = [e for e in ledger_events if e["action_status"] == "SEAL_COMPLETED"]
    assert len(completed_events_after_restart) == 0, "SEAL_COMPLETED was somehow dispatched!"
    print("✅ Test 2 Passed: Outbox shows tamper-evident anomaly (missing SEAL_COMPLETED).")
    
    import sqlite3
    db = sqlite3.connect("daemon/queue.db")
    c = db.cursor()
    c.execute("SELECT action_status FROM local_audit_log")
    statuses = [row[0] for row in c.fetchall()]
    assert "SEAL_REQUESTED" in statuses, "Tamper evident anomaly not found: SEAL_REQUESTED missing!"
    assert "SEAL_COMPLETED" not in statuses, "SEAL_COMPLETED should NOT be present after recovery!"
    
    print("✅ Test 2 Passed: Execution crash anomaly is locally detectable.")

if __name__ == "__main__":
    start_mock_ledger()
    print("--- Running Crash-Window Tests ---")
    run_test_1()
    run_test_2()
    print("🚀 All Crash-Window Tests Passed!")
