from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from nacl.signing import VerifyKey, SigningKey
from nacl.exceptions import BadSignatureError
import binascii
import time
import sqlite3
import os
import json

app = FastAPI(title="Autonomous Agent Accountability Remote Ledger")

# --- DATABASE SETUP ---
DB_PATH = os.environ.get("LEDGER_DB_PATH", "ledger.db")

# Ensure the parent directory of DB_PATH exists
db_dir = os.path.dirname(DB_PATH)
if db_dir:
    os.makedirs(db_dir, exist_ok=True)

con = sqlite3.connect(DB_PATH, check_same_thread=False)

# Enable WAL mode for safe concurrency
con.execute("PRAGMA journal_mode=WAL;")

con.execute("""
    CREATE TABLE IF NOT EXISTS events (
        nonce TEXT,
        payload_hash TEXT,
        agent_id TEXT,
        local_timestamp INTEGER,
        device_id TEXT,
        device_signature TEXT,
        receipt_signature TEXT,
        ledger_timestamp INTEGER,
        previous_hash TEXT,
        chain_hash TEXT,
        action_status TEXT DEFAULT 'UNKNOWN',
        PRIMARY KEY (nonce, action_status)
    )
""")
con.commit()

# Migration for older schema that used `nonce TEXT PRIMARY KEY`
try:
    # Check if the table exists and if nonce is the only PK
    cur = con.cursor()
    cur.execute("PRAGMA table_info(events)")
    columns = cur.fetchall()
    pk_count = sum(1 for col in columns if col[5] > 0)
    
    if pk_count == 1:
        # We need to migrate to composite PK
        con.execute("DROP TRIGGER IF EXISTS prevent_events_update")
        con.execute("DROP TRIGGER IF EXISTS prevent_events_delete")
        con.execute("ALTER TABLE events RENAME TO events_old")
        con.execute("""
            CREATE TABLE events (
                nonce TEXT,
                payload_hash TEXT,
                agent_id TEXT,
                local_timestamp INTEGER,
                device_id TEXT,
                device_signature TEXT,
                receipt_signature TEXT,
                ledger_timestamp INTEGER,
                previous_hash TEXT,
                chain_hash TEXT,
                action_status TEXT DEFAULT 'UNKNOWN',
                PRIMARY KEY (nonce, action_status)
            )
        """)
        con.execute("INSERT INTO events SELECT * FROM events_old")
        con.execute("DROP TABLE events_old")
        con.commit()
except Exception as e:
    import sys
    print(f"Migration error: {e}", file=sys.stderr)
    pass

for col in ["previous_hash TEXT", "chain_hash TEXT", "action_status TEXT DEFAULT 'UNKNOWN'"]:
    try:
        con.execute(f"ALTER TABLE events ADD COLUMN {col};")
        con.commit()
    except sqlite3.OperationalError:
        pass

# Ensure Immutability at the DB engine level
con.execute("""
    CREATE TRIGGER IF NOT EXISTS prevent_events_update
    BEFORE UPDATE ON events
    BEGIN
        SELECT RAISE(ABORT, 'events table is strictly append-only (immutable)');
    END;
""")
con.execute("""
    CREATE TRIGGER IF NOT EXISTS prevent_events_delete
    BEFORE DELETE ON events
    BEGIN
        SELECT RAISE(ABORT, 'events table is strictly append-only (immutable)');
    END;
""")
con.commit()

# --- KEYS AND REGISTRY (Loaded from ENV) ---
LEDGER_PRIVATE_HEX = os.environ.get("LEDGER_PRIVATE_KEY")
if not LEDGER_PRIVATE_HEX:
    print("CRITICAL: LEDGER_PRIVATE_KEY not set. Halting startup.")
    exit(1)

ledger_sk = SigningKey(binascii.unhexlify(LEDGER_PRIVATE_HEX))

# Load device registry from JSON env
devices_json = os.environ.get("AUTHORIZED_DEVICES_JSON", "{}")
try:
    AUTHORIZED_DEVICES = json.loads(devices_json)
except json.JSONDecodeError:
    print("WARNING: AUTHORIZED_DEVICES_JSON is invalid JSON.")
    AUTHORIZED_DEVICES = {}

# --- SCHEMAS ---
class SealRequest(BaseModel):
    payload_hash: str = Field(..., pattern=r'^[a-f0-9]{64}$')
    agent_id: str = Field(..., min_length=1, max_length=128)
    local_timestamp: int
    nonce: str = Field(..., pattern=r'^[a-f0-9\-]{36}$') # UUID
    device_id: str = Field(..., min_length=1, max_length=128)
    device_signature: str = Field(..., pattern=r'^[a-f0-9]{128}$')
    action_status: str = Field("UNKNOWN", max_length=32)

class LeaseRequest(BaseModel):
    device_id: str

@app.post("/lease")
async def request_lease(req: LeaseRequest):
    print(f"DEBUG LEDGER: Received /lease for {req.device_id}", flush=True)
    device_vk_hex = AUTHORIZED_DEVICES.get(req.device_id)
    if not device_vk_hex:
        raise HTTPException(status_code=401, detail="Kill-switch engaged. Agent authorization revoked.")
        
    expires_at = int(time.time()) + 30
    msg = f"LEASE:{req.device_id}:{expires_at}".encode()
    sig = binascii.hexlify(ledger_sk.sign(msg).signature).decode()
    return {
        "expires_at": expires_at,
        "lease_signature": sig
    }

@app.post("/seal")
async def seal_event(req: SealRequest):
    print(f"DEBUG LEDGER: Received /seal for {req.nonce} status {req.action_status}", flush=True)
    # 1. Device Public Key Lookup
    device_vk_hex = AUTHORIZED_DEVICES.get(req.device_id)
    if not device_vk_hex:
        raise HTTPException(status_code=401, detail="Unknown device ID")

    # 2. PKI Verification (Ed25519)
    message = f"{req.payload_hash}:{req.local_timestamp}:{req.device_id}:{req.nonce}:{req.agent_id}:{req.action_status}".encode('utf-8')
    try:
        verify_key = VerifyKey(binascii.unhexlify(device_vk_hex))
        signature_bytes = binascii.unhexlify(req.device_signature)
        verify_key.verify(message, signature_bytes)
    except (BadSignatureError, binascii.Error):
        raise HTTPException(status_code=401, detail="Invalid device signature")

    # 3. Ledger Countersign & Merkle Hash Chain
    ledger_timestamp = int(time.time())
    
    import hashlib
    cur = con.cursor()
    cur.execute("BEGIN EXCLUSIVE;")
    try:
        cur.execute("SELECT chain_hash FROM events ORDER BY rowid DESC LIMIT 1")
        last_row = cur.fetchone()
        previous_hash = last_row[0] if (last_row and last_row[0]) else ("0" * 64)
        
        hasher = hashlib.sha256()
        hasher.update(previous_hash.encode())
        hasher.update(req.payload_hash.encode())
        hasher.update(req.nonce.encode())
        hasher.update(req.action_status.encode())
        hasher.update(str(ledger_timestamp).encode())
        chain_hash = hasher.hexdigest()

        # 4. Generate Receipt
        receipt_message = f"{req.payload_hash}:{req.agent_id}:{req.local_timestamp}:{req.device_id}:{req.nonce}:{req.device_signature}:{ledger_timestamp}:{chain_hash}:{req.action_status}".encode('utf-8')
        receipt_signature_bytes = ledger_sk.sign(receipt_message).signature
        receipt_signature = binascii.hexlify(receipt_signature_bytes).decode('utf-8')

        # 5. Append-Only Persistence
        cur.execute("""
            INSERT INTO events (
                nonce, payload_hash, agent_id, local_timestamp, device_id, 
                device_signature, receipt_signature, ledger_timestamp,
                previous_hash, chain_hash, action_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            req.nonce, req.payload_hash, req.agent_id, req.local_timestamp, req.device_id,
            req.device_signature, receipt_signature, ledger_timestamp,
            previous_hash, chain_hash, req.action_status
        ))
        con.commit()
        
        if os.environ.get("FAULT_INJECT_DROP_RESPONSE") == "1":
            import os as system_os
            import signal
            system_os.kill(system_os.getpid(), signal.SIGKILL)
    except sqlite3.IntegrityError:
        con.rollback()
        cur.execute("SELECT payload_hash, agent_id, local_timestamp, device_id, device_signature, receipt_signature, ledger_timestamp, chain_hash, action_status FROM events WHERE nonce = ? AND action_status = ?", (req.nonce, req.action_status))
        row = cur.fetchone()
        if row:
            if (row[0] == req.payload_hash and row[1] == req.agent_id and row[2] == req.local_timestamp and 
                row[3] == req.device_id and row[4] == req.device_signature and row[8] == req.action_status):
                return {
                    "status": "sealed",
                    "receipt_signature": row[5],
                    "ledger_timestamp": row[6],
                    "chain_hash": row[7],
                    "idempotent": True
                }
        raise HTTPException(status_code=409, detail="Duplicate nonce+status with mismatched fields. Replay attack rejected.")
    except Exception as e:
        import sys
        print(f"Exception during seal: {e}", file=sys.stderr)
        con.rollback()
        raise HTTPException(status_code=500, detail="Database Error")

    return {
        "status": "sealed",
        "receipt_signature": receipt_signature,
        "ledger_timestamp": ledger_timestamp,
        "chain_hash": chain_hash
    }

@app.get("/")
def health_check():
    import hashlib
    vk_bytes = ledger_sk.verify_key.encode()
    fingerprint = hashlib.sha256(vk_bytes).hexdigest()
    return {
        "status": "Autonomous Agent Accountability Ledger Online",
        "ledger_public_key_fingerprint": fingerprint
    }

@app.get("/logs")
def get_logs():
    cur = con.cursor()
    cur.execute("SELECT nonce, payload_hash, agent_id, local_timestamp, device_id, device_signature, receipt_signature, ledger_timestamp, previous_hash, chain_hash, action_status FROM events ORDER BY ledger_timestamp DESC LIMIT 100")
    rows = cur.fetchall()
    logs = []
    for row in rows:
        logs.append({
            "nonce": row[0],
            "payload_hash": row[1],
            "agent_id": row[2],
            "local_timestamp": row[3],
            "device_id": row[4],
            "device_signature": row[5],
            "receipt_signature": row[6],
            "ledger_timestamp": row[7],
            "previous_hash": row[8],
            "chain_hash": row[9],
            "action_status": row[10]
        })
    return {"logs": logs}
