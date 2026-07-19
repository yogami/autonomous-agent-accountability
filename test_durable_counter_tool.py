#!/usr/bin/env python3
import sys
import json
import sqlite3
import os

DB_PATH = os.environ.get("COUNTER_DB_PATH", "counter.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS counter (id INTEGER PRIMARY KEY, count INTEGER)")
    conn.execute("INSERT OR IGNORE INTO counter (id, count) VALUES (1, 0)")
    conn.commit()
    return conn

def main():
    conn = init_db()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            if req.get("method") == "tools/call":
                # Increment counter durably
                conn.execute("UPDATE counter SET count = count + 1 WHERE id = 1")
                conn.commit()
                cur = conn.cursor()
                cur.execute("SELECT count FROM counter WHERE id = 1")
                count = cur.fetchone()[0]
                
                resp = {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "result": {"count": count, "status": "executed"}
                }
                print(json.dumps(resp), flush=True)
            else:
                # Echo for other messages
                resp = {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "result": "ignored"
                }
                print(json.dumps(resp), flush=True)
        except Exception as e:
            # Output error strictly formatted as JSON-RPC error if possible
            if 'req' in locals() and isinstance(req, dict) and 'id' in req:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": req["id"],
                    "error": {"code": -32000, "message": str(e)}
                }
                print(json.dumps(err_resp), flush=True)

if __name__ == "__main__":
    main()
