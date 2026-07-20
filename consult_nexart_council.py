import os
import urllib.request
import urllib.error
import json

def query_openrouter(model_id, system_prompt, user_prompt):
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        return f"Error: OPENROUTER_API_KEY not found in environment."

    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "AgentWitness Audit"
    }
    
    data = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    }
    
    req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))
            return result["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        return f"HTTP Error {e.code}: {e.reason}\nDetails: {error_body}"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    def read_file(path):
        with open(path, "r") as f:
            return f.read()

    spec_text = read_file("spec.md")
    tdd_text = read_file("test_nexart_parity.py")
    ui_text = read_file("ledger/main.py")
    bundle_text = read_file("create_bundle.py")
    anchor_text = read_file("anchor_ledger.py")

    system_prompt = "You are Fable 5 (Anthropic Claude), a brutally honest, cynical Silicon Valley principal engineer and security auditor."
    user_prompt = f"""We are building an Irreversibility Firewall called AgentWitness. Our main competitor is nexart.io. 
Our objective is to EVEN UP with nexart.io by adding Public Verification Portals, Project Bundles, and Decentralized Anchoring.

Previously, you gave us 3 mandatory changes: Zero-Trust Portal, Canonicalization, and OpenTimestamps.
We have implemented them all.

Here is the updated spec:
{spec_text}

Here is the TDD test suite:
{tdd_text}

Here is the ledger UI (ledger/main.py) with the Zero-Trust Portal:
{ui_text}

Here is the bundle generator (create_bundle.py) with canonicalization:
{bundle_text}

Here is the anchoring script (anchor_ledger.py) with OpenTimestamps:
{anchor_text}

Review this implementation. Does this meet your brutal standards and achieve parity with Nexart? 
If there are any cryptographic flaws, tell us to fix them. DO NOT force a greenlight if it sucks. 
If it is mathematically sound and production-ready, give us the explicit 'GREENLIGHT'."""

    print("Querying Anthropic Claude Fable 5 on OpenRouter...")
    response = query_openrouter("anthropic/claude-fable-5", system_prompt, user_prompt)
    print("\n--- Fable 5 Feedback ---\n")
    print(response)

if __name__ == "__main__":
    main()
