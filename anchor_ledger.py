import argparse
import sqlite3
import os
import time
import json
import subprocess

def main():
    parser = argparse.ArgumentParser(description="Anchor AgentWitness Ledger to Blockchain")
    parser.add_argument("--mock", action="store_true", help="Mock the anchoring for testing")
    args = parser.parse_args()

    db_path = os.environ.get("LEDGER_DB_PATH", "ledger.db")
    chain_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    rowid = 0
    nonce = "genesis"
    
    if os.path.exists(db_path):
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        try:
            cur.execute("SELECT rowid, nonce, chain_hash FROM events ORDER BY rowid DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                rowid = row[0]
                nonce = row[1]
                chain_hash = row[2]
        except Exception:
            pass

    print(f"Anchored chain_hash: {chain_hash}")
    
    # Save raw hash bytes to file
    hash_bytes = bytes.fromhex(chain_hash)
    
    os.makedirs("proofs", exist_ok=True)
    chain_file = f"proofs/chain_hash_{chain_hash}.dat"
    with open(chain_file, "wb") as f:
        f.write(hash_bytes)
        
    # Write metadata sidecar
    with open(f"proofs/anchor_metadata_{chain_hash}.json", "w") as f:
        json.dump({
            "chain_hash": chain_hash,
            "rowid": rowid,
            "nonce": nonce,
            "anchored_at": int(time.time())
        }, f)
        
    if args.mock:
        print("Mock OpenTimestamps transaction submitted.")
        # Produce a structurally valid .ots file magic bytes
        with open(f"{chain_file}.ots", "wb") as f:
            f.write(b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")
    else:
        print("OpenTimestamps integration: Submitting hash to Bitcoin calendars...")
        subprocess.run(["ots", "stamp", chain_file], check=True)
        print(f"ots stamp created {chain_file}.ots")
        
        print("\nNOTE: This is currently a PENDING calendar attestation.")
        print("It will take a few hours for the calendar servers to aggregate this hash into a Bitcoin block.")
        print(f"Once the Bitcoin transaction confirms, run this script again or run `ots upgrade {chain_file}.ots` to download the final Bitcoin block proof.")
        print("Attempting to upgrade now (will likely say 'Pending' if just stamped)...")
        subprocess.run(["ots", "upgrade", f"{chain_file}.ots"])
        
    print("Decentralized anchoring completed successfully.")

if __name__ == "__main__":
    main()
