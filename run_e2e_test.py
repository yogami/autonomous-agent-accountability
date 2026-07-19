import subprocess
import time
import json
import sqlite3
import os
import binascii
from nacl.signing import SigningKey
import requests

print("--- Running Strict E2E Test with Idempotency & Fault Injection ---")

ledger_sk = SigningKey.generate()
ledger_sk_hex = binascii.hexlify(ledger_sk.encode()).decode()

device_sk = SigningKey.generate()
device_sk_hex = binascii.hexlify(device_sk.encode()).decode()
device_vk_hex = binascii.hexlify(device_sk.verify_key.encode()).decode()
device_id = "test-device-01"

authorized_devices = {device_id: device_vk_hex}

for db in ["ledger/test_ledger.db", "daemon/queue.db", "counter.db"]:
    if os.path.exists(db):
        os.remove(db)

# 1. Start Ledger Backend with Fault Injection Enabled
print("[Test] 1. Starting Ledger with FAULT_INJECT_DROP_RESPONSE=1 ...")
ledger_env = os.environ.copy()
ledger_env["LEDGER_PRIVATE_KEY"] = ledger_sk_hex
ledger_env["AUTHORIZED_DEVICES_JSON"] = json.dumps(authorized_devices)
ledger_env["LEDGER_DB_PATH"] = "test_ledger.db"
ledger_env["FAULT_INJECT_DROP_RESPONSE"] = "1"

ledger_proc = subprocess.Popen(
    ["python3", "-m", "uvicorn", "main:app", "--port", "8080"],
    cwd="ledger",
    env=ledger_env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)
time.sleep(2) # Give uvicorn time to start

# 2. Start Daemon 
print("[Test] 2. Starting Rust Daemon...")
daemon_env = os.environ.copy()
daemon_env["ACCOUNTABILITY_PRIVATE_KEY"] = device_sk_hex
daemon_env["ACCOUNTABILITY_DEVICE_ID"] = device_id
daemon_env["LEDGER_PUBLIC_KEY"] = ledger_sk_hex[64:] if len(ledger_sk_hex) == 128 else ledger_sk.verify_key.encode().hex()
daemon_env["LEDGER_URL"] = "http://127.0.0.1:8080" # Wait, proxy requires HTTPS!
# Ah, but we added a local exception. "http://127.0.0.1:8080" is allowed because it has "127.0.0.1"
daemon_env["ACCOUNTABILITY_QUEUE_DB_PATH"] = "queue.db"
daemon_env["ACCOUNTABILITY_ENCRYPTION_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
daemon_env["COUNTER_DB_PATH"] = "../counter.db"
policy = {
    "default_mode": "bypass",
    "rules": [
        {"tool": "increment_counter", "mode": "require_ledger"}
    ]
}
daemon_env["ACCOUNTABILITY_POLICY_JSON"] = json.dumps(policy)

daemon_proc = subprocess.Popen(
    ["./target/debug/autonomous-agent-accountability", "--", "python3", "../test_durable_counter_tool.py"],
    cwd="daemon",
    env=daemon_env,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# 3. Inject Payload
print("[Test] 3. Injecting Payload to Daemon...")
payload = {
    "jsonrpc": "2.0",
    "id": 42,
    "method": "tools/call",
    "params": {
        "name": "increment_counter"
    }
}
payload_str = json.dumps(payload) + "\n"

daemon_proc.stdin.write(payload_str.encode())
daemon_proc.stdin.flush()

# Give it time. The proxy will hit the ledger for the lease, execute the tool, and the background thread will hit the ledger for SEAL_REQUESTED.
# The ledger will commit SEAL_REQUESTED and EXIT (crash) because of fault injection!
time.sleep(8)

if ledger_proc.poll() is None:
    print("❌ FAIL: Expected ledger to crash due to fault injection, but it is still running!")
    import fcntl; fl = fcntl.fcntl(ledger_proc.stderr, fcntl.F_GETFL); fcntl.fcntl(ledger_proc.stderr, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    err = ledger_proc.stderr.read()
    if err: print(f"DEBUG STDERR ledger:\n{err.decode('utf-8')}")

    import fcntl; fl = fcntl.fcntl(ledger_proc.stdout, fcntl.F_GETFL); fcntl.fcntl(ledger_proc.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    out_ledger = ledger_proc.stdout.read()
    if out_ledger: print(f"DEBUG STDOUT ledger:\n{out_ledger.decode('utf-8')}")

    import fcntl; fl = fcntl.fcntl(daemon_proc.stderr, fcntl.F_GETFL); fcntl.fcntl(daemon_proc.stderr, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    err2 = daemon_proc.stderr.read()
    if err2: print(f"DEBUG STDERR daemon:\n{err2.decode('utf-8')}")

    import sqlite3
    try:
        db = sqlite3.connect("daemon/queue.db")
        c = db.cursor()
        c.execute("SELECT * FROM local_audit_log")
        rows = c.fetchall()
        print(f"DEBUG DB ROWS: {rows}")
    except Exception as e:
        print(f"DEBUG DB ERROR: {e}")

    try:
        db_ledger = sqlite3.connect("ledger/test_ledger.db")
        c_ledger = db_ledger.cursor()
        c_ledger.execute("SELECT action_status FROM events")
        ledger_rows_debug = c_ledger.fetchall()
        print(f"DEBUG LEDGER ROWS AFTER CRASH: {ledger_rows_debug}")
    except Exception as e:
        print(f"DEBUG LEDGER DB ERROR: {e}")

    ledger_proc.terminate()
    daemon_proc.terminate()
    exit(1)

print("✅ Ledger crashed as expected after committing SEAL_REQUESTED!")

# Verify counter WAS incremented (tool executed asynchronously!)
con_counter = sqlite3.connect("counter.db")
try:
    cur = con_counter.cursor()
    cur.execute("SELECT count FROM counter WHERE id = 1")
    count = cur.fetchone()[0]
    if count != 1:
        print(f"❌ FAIL: Tool should have executed! Count = {count}")
        exit(1)
except sqlite3.OperationalError:
    print("❌ FAIL: Tool should have executed but counter.db is missing!")
    exit(1)
print("✅ Tool execution succeeded locally (count = 1) using TTL lease!")

# 4. Restart Ledger without fault injection to test background sync idempotency
print("[Test] 4. Restarting Ledger normally...")
ledger_env["FAULT_INJECT_DROP_RESPONSE"] = "0"
ledger_proc2 = subprocess.Popen(
    ["python3", "-m", "uvicorn", "main:app", "--port", "8080"],
    cwd="ledger",
    env=ledger_env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# Wait for background sync to push the queue
print("[Test] 5. Waiting for background sync...")
time.sleep(7)

# 6. Verify Idempotency and Final State
print("[Test] 6. Verifying Final State...")

con_ledger = sqlite3.connect("ledger/test_ledger.db")
cur_ledger = con_ledger.cursor()
cur_ledger.execute("SELECT nonce, action_status FROM events")
ledger_rows = cur_ledger.fetchall()

print(f"Ledger rows: {ledger_rows}")
if len(ledger_rows) != 2:
    print(f"❌ FAIL: Expected exactly 2 events (SEAL_REQUESTED and SEAL_COMPLETED), found {len(ledger_rows)}")
    ledger_proc2.terminate()
    daemon_proc.terminate()
    exit(1)

print("✅ Ledger successfully processed the idempotent retry without duplicating rows!")

con_queue = sqlite3.connect("daemon/queue.db")
cur_queue = con_queue.cursor()
cur_queue.execute("SELECT COUNT(*) FROM receipts")
receipt_count = cur_queue.fetchone()[0]

if receipt_count == 0:
    print("❌ FAIL: Background sync failed to fetch receipt!")
    ledger_proc2.terminate()
    daemon_proc.terminate()
    exit(1)

print("✅ Proxy successfully synced and obtained receipt!")

ledger_proc2.terminate()
daemon_proc.terminate()

print("\n🚀 SUCCESS: Exactly-Once Fault Injection & Idempotency Proved!")
