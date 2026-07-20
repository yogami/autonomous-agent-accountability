# AgentWitness: The Irreversibility Firewall

Look, most "AI Safety" projects put a slow approval gate in front of every single action an agent takes. That introduces horrible network latency. It dies in prod. Nobody actually uses it. 

We got annoyed by that, so we built **AgentWitness**. It acts as an Irreversibility Firewall for any Autonomous AI Agent using the Model Context Protocol.

**✅ Railway Deployment Status: LIVE**
**Live Ledger URL:** `https://autonomous-ledger-production.up.railway.app`
*(It's running 24/7 on Railway right now. We mapped persistent volume mounts so the DB won't wipe).*

## Architecture 

Here is the deal. We split the problem in half:

1. **The Remote Ledger (`/ledger`):** This is a FastAPI/SQLite cloud service running permanently on Railway. It issues cryptographically signed, short-lived **TTL Leases** to authorize execution. It also acts as an append-only, tamper-evident audit log.
2. **The MCP Proxy/Daemon (`/daemon`):** This is a fast Rust middleware. **It runs locally** exactly where your AI Agent runs. It intercepts `tools/call` events on the fly and classifies them using a default-deny policy engine. 
    * **Reversible Actions** (like reading files or small transactions): The proxy executes them instantly. Zero network lag.
    * **Irreversible Actions** (like `execute_wire_transfer($10M)`): The proxy checks its cryptographically signed TTL Lease. If the lease is good, it executes immediately and dumps the audit event (`SEAL_REQUESTED` and `SEAL_COMPLETED`) to the remote ledger. If the ledger is offline? No problem. It queues the event in a local durable `queue.db` so the agent never blocks.
    * **Kill-Switch**: If we revoke a lease, the proxy shuts it down within 30 seconds. The system fails closed.

*(Note: We block destructive state changes like file writes or wire transfers. Read-only actions are technically irreversible in terms of data exfiltration. If a rogue agent leaks data via standard output, that bypasses the firewall. Our goal was bounding the destructive blast radius, not stopping read-only exfiltration).*

## Declarative Parameter-Aware Policy
The proxy uses an `ACCOUNTABILITY_POLICY_JSON` file. It defaults to deny (meaning it requires the ledger) but you can bypass the ledger for specific tools or specific *arguments* to tools. For example, skip the ledger for wire transfers under $100:
```json
{
  "default_mode": "require_ledger",
  "rules": [
    {
      "tool": "execute_wire_transfer",
      "mode": "bypass_if",
      "bypass_condition": {
        "param": "amount",
        "less_than": 100.0
      }
    }
  ]
}
```

---

## How Codex & GPT-5.6 Were Used
As required by the hackathon rules, here is exactly how we integrated Codex and GPT-5.6 into the stack:

1. **Securing the Codex Agent Environment:** OpenAI's Codex acts as a crazy powerful command center for agentic coding. Our accountability proxy safely wraps agentic workflows like those orchestrated by Codex. When Codex generates raw, potentially dangerous `tools/call` JSON-RPC payloads, our proxy intercepts, parses, and blocks or allows them in real-time based on the crypto policy.
2. **Zero-Trust Portal Refactoring:** I used Codex specifically to help me iterate on a rigorous Zero-Trust architecture, resolving issues like DOM-based XSS, signature stripping, and chain truncation vulnerabilities. Codex helped me completely decouple the verification portal from the Ledger into a standalone `verifier.html` and implement strict regex checks against delimiter injection in the Pydantic schemas.
3. **Agentic Code Generation:** I honestly built the core Rust daemon's async interception logic and the FastAPI remote ledger's crypto handshakes iteratively. I explicitly burned credits on OpenRouter calling **GPT-5.6 Terra and Sol** models, using Codex as my primary IDE and agentic coding system to architect the whole stack.

---

## Installation & Testing for Judges

To test this, **you have to run the proxy daemon locally on your machine** alongside our test scripts. I wrote a quick setup script so you don't have to compile everything manually.

### 1. One-Liner Daemon Installation
Install the Rust daemon and testing suite instantly:

```bash
curl -sSL https://raw.githubusercontent.com/yogami/autonomous-agent-accountability/main/setup.sh | bash
```
*(If you hate piping to bash, just clone the repo and run `chmod +x setup.sh && ./setup.sh`)*

### 2. Verify Fault Injection & Crash Resilience
We wrote this script to inject an artificial `SIGKILL` crash into the daemon exactly midway through executing a tool. It proves that our local `queue.db` successfully recovers the state without blocking the AI agent or dropping events.

```bash
python3 test_crash_windows.py
```

### 3. Run the Strict End-to-End Idempotency Test
This script spins up the entire pipeline, simulates a network partition where the remote ledger crashes *after* receiving a transaction but before responding, and proves the local proxy gracefully recovers and enforces exactly-once execution.

```bash
python3 run_e2e_test.py
```

### 4. Run the Adversarial Security Proofs
This script proves that the Rust proxy strictly **fails closed**. It spoofs various invalid states and verifies the payload never reaches the underlying tool process.

```bash
python3 test_adversarial_proxy.py
```
This tests:
1. Revoked/Unauthorized Device ID (Kill-switch execution)
2. Valid device, but forged Ledger cryptographic receipt
3. Out-of-bounds parameter execution (Policy engine blocks it)

---

## Frequently Asked Questions

**Q: What is the primary threat model this defends against?**
The firewall specifically targets unauthorized, irreversible state changes (like executing `rm -rf`, modifying production databases, or initiating wire transfers). It utilizes TTL leases, default-deny parameter policies, and cryptographic hashes to guarantee that destructive actions cannot happen without leaving a permanent, undeniable cryptographic receipt.

**Q: Where is the local audit database stored?**
The proxy writes to `queue.db` directly on your host filesystem. Because the proxy is deployed natively alongside the AI agent, this is a permanent local storage mechanism that survives reboots.

**Q: Is the remote database secure from tampering?**
The SQLite database engine itself enforces immutability using `BEFORE UPDATE` and `BEFORE DELETE` triggers that just call `RAISE(ABORT)`. Plus, every row contains a `chain_hash` derived from the previous row's hash. If you manually edit the DB, it breaks the crypto verification completely.
