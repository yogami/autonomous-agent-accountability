import json
import uuid
import time
import urllib.request
import binascii
from nacl.signing import SigningKey

LIVE_URL = "https://autonomous-ledger-production.up.railway.app"

print(f"[Test] 1. Checking health of {LIVE_URL}...")
req = urllib.request.Request(f"{LIVE_URL}/")
with urllib.request.urlopen(req) as response:
    print(response.read().decode())

print("[Test] 2. Checking logs...")
req = urllib.request.Request(f"{LIVE_URL}/logs")
with urllib.request.urlopen(req) as response:
    logs = json.loads(response.read().decode())
    print(f"Found {len(logs)} events in the remote ledger!")

