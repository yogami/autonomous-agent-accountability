import argparse
import json
import sqlite3
import os
import sys
import httpx
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder

def verify_raw_string(pubkey_hex, signature_hex, raw_msg):
    try:
        vk = VerifyKey(pubkey_hex, encoder=HexEncoder)
        vk.verify(raw_msg.encode('utf-8'), bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False

def emit_divergence_report(message, local_record=None, remote_log=None):
    report = {
        "error": "DIVERGENCE DETECTED",
        "message": message,
        "local_record": local_record,
        "remote_log": remote_log
    }
    with open("divergence_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"DIVERGENCE DETECTED: {message}")
    print("Divergence report written to divergence_report.json")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Generate AgentWitness Project Bundle")
    parser.add_argument("--output", required=True, help="Output bundle file path")
    parser.add_argument("--mock", action="store_true", help="Generate a mock bundle for testing")
    parser.add_argument("--remote-url", default="http://localhost:8000", help="Remote ledger URL")
    parser.add_argument("--ledger-pubkey", help="Hex string of the Trusted Ledger Public Key")
    args = parser.parse_args()

    if not args.mock and not args.ledger_pubkey:
        parser.error("--ledger-pubkey is required unless --mock is used")

    bundle = {
        "format_version": "1.0",
        "ledger_pubkey": args.ledger_pubkey or "mock_ledger_pubkey_hex",
        "records": []
    }

    if args.mock:
        # Generate structurally valid mock with real Ed25519 signature
        from nacl.signing import SigningKey
        
        mock_sk = SigningKey.generate()
        mock_vk = mock_sk.verify_key.encode().hex()
        
        ledger_sk = SigningKey.generate()
        ledger_vk = ledger_sk.verify_key.encode().hex()
        bundle["ledger_pubkey"] = ledger_vk
        
        raw_msg = f"{'a'*64}:1234567890:{mock_vk}:mock-uuid:mock_agent:OK"
        mock_sig = mock_sk.sign(raw_msg.encode('utf-8')).signature.hex()
        
        ledger_msg = f"{'a'*64}:mock_agent:1234567890:{mock_vk}:mock-uuid:{mock_sig}:1234567891:chain_mock:OK"
        mock_receipt_sig = ledger_sk.sign(ledger_msg.encode('utf-8')).signature.hex()
        
        bundle["records"] = [{
            "nonce": "mock-uuid",
            "payload_hash": "a"*64,
            "ts": 1234567890,
            "device_id": "mock_device",
            "agent_id": "mock_agent",
            "status": "OK",
            "signature": mock_sig,
            "receipt_signature": mock_receipt_sig,
            "ledger_timestamp": 1234567891,
            "previous_hash": "0"*64,
            "chain_hash": "chain_mock"
        }]
    else:
        # Load authorized devices registry
        devices_json = os.environ.get("AUTHORIZED_DEVICES_JSON", "{}")
        try:
            AUTHORIZED_DEVICES = json.loads(devices_json)
        except json.JSONDecodeError:
            AUTHORIZED_DEVICES = {}
        db_path = os.environ.get("ACCOUNTABILITY_QUEUE_DB_PATH", "queue.db")
        if not os.path.exists(db_path):
            print("No local queue.db found.")
            sys.exit(1)
            
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        
        # 1. Read local records
        local_records = {}
        try:
            cur.execute("SELECT nonce, payload_hash, ts, device_id, agent_id, status, signature FROM local_events")
            for row in cur.fetchall():
                key = (row[0], row[5]) # (nonce, action_status)
                local_records[key] = {
                    "nonce": row[0],
                    "payload_hash": row[1],
                    "ts": row[2],
                    "device_id": row[3],
                    "agent_id": row[4],
                    "status": row[5],
                    "signature": row[6]
                }
        except Exception:
            pass
            
        # 2. Fetch remote /logs
        try:
            r = httpx.get(f"{args.remote_url}/logs", timeout=10)
            remote_resp = r.json()
            remote_logs = remote_resp.get("logs", [])
        except Exception as e:
            print(f"Failed to fetch remote logs: {e}")
            sys.exit(1)
            
        # 3. Bidirectional Divergence check & Signature Verification
        remote_nonces = set()
        
        # Check Local against Remote
        for log in remote_logs:
            nonce = log.get("nonce")
            action_status = log.get("action_status")
            key = (nonce, action_status)
            remote_nonces.add(key)
            
            if key not in local_records:
                emit_divergence_report(f"Remote record {key} not found locally. (Possible rogue agent action)", remote_log=log)
                
            local = local_records[key]
            if local["payload_hash"] != log.get("payload_hash"):
                emit_divergence_report(f"Payload hash mismatch for {key}.", local_record=local, remote_log=log)
                
            # Device identity check
            device_pubkey_hex = AUTHORIZED_DEVICES.get(local['device_id'])
            if not device_pubkey_hex:
                emit_divergence_report(f"Device ID '{local['device_id']}' not found in trusted registry.", local_record=local)
                
            # Verify device signature over raw string
            raw_msg = f"{local['payload_hash']}:{local['ts']}:{local['device_id']}:{local['nonce']}:{local['agent_id']}:{local['status']}"
            if not verify_raw_string(device_pubkey_hex, local['signature'], raw_msg):
                emit_divergence_report(f"INVALID DEVICE SIGNATURE for {key} against trusted registry key.", local_record=local)
                
            # Verify ledger receipt signature if pubkey is provided
            local["receipt_signature"] = log.get("receipt_signature")
            local["ledger_timestamp"] = log.get("ledger_timestamp")
            local["previous_hash"] = log.get("previous_hash")
            local["chain_hash"] = log.get("chain_hash")
            
            if args.ledger_pubkey:
                receipt_msg = f"{local['payload_hash']}:{local['agent_id']}:{local['ts']}:{local['device_id']}:{local['nonce']}:{local['signature']}:{local['ledger_timestamp']}:{local['chain_hash']}:{local['status']}"
                if not verify_raw_string(args.ledger_pubkey, local['receipt_signature'], receipt_msg):
                    emit_divergence_report(f"INVALID LEDGER RECEIPT SIGNATURE for {key}", local_record=local, remote_log=log)
            
            bundle["records"].append(local)
            
        # Check Remote against Local
        for key in local_records.keys():
            if key not in remote_nonces:
                emit_divergence_report(f"Local record {key} not found remotely. (Possible ledger equivocation/censorship)", local_record=local_records[key])

    with open(args.output, "w") as f:
        json.dump(bundle, f, indent=2)
    print(f"Successfully exported {len(bundle['records'])} records to {args.output}")
    if not args.mock:
        print("Divergence Check: PASSED (Local and remote match exactly).")

if __name__ == "__main__":
    main()
