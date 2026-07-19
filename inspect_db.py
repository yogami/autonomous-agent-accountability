import sqlite3
import json

conn = sqlite3.connect("daemon/queue.db")
c = conn.cursor()
c.execute("SELECT nonce, action_status, payload_json FROM local_audit_log")
rows = c.fetchall()
for row in rows:
    print(f"Row: {row}")

c.execute("SELECT json_extract(payload_json, '$.id') FROM local_audit_log")
rows2 = c.fetchall()
for row in rows2:
    print(f"Extracted ID: {row}")
