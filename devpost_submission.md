## Inspiration
With the release of GPT-5.6 and the integration of Codex into ChatGPT, AI agents are no longer just chatbots—they are autonomous actors. Through the Model Context Protocol (MCP), these agents now have direct access to local developer environments: executing shell commands, modifying filesystems, and accessing production SSH keys.

But granting autonomy without liability is catastrophic. If an agent executes a destructive command, who is responsible? The model provider? The tool vendor? The developer?

Currently, AWS and Microsoft can only log what happens inside their own cloud APIs. They have zero visibility into what a local agent does on a developer's machine via stdio pipes. We realized the ecosystem desperately needed a "Flight Data Recorder" for autonomous AI. We were inspired to build AgentWitness: a cryptographically sealed, OS-level liability ledger and Irreversibility Firewall that secures the seam between the AI brain and the local operating system.

## What it does
AgentWitness acts as an **Irreversibility Firewall** for any Autonomous AI Agent using the Model Context Protocol. It splits accountability into three distinct components:

1. **The MCP Proxy/Daemon (Local):** A Rust middleware that sits at the OS kernel layer. It wraps the raw stdio pipes that MCP servers use to communicate. It intercepts JSON-RPC `tools/call` events and classifies them using a default-deny, parameter-aware policy engine.
2. **The Remote Ledger:** A FastAPI cloud service that issues cryptographically signed, short-lived **TTL Leases** for agent execution. For irreversible actions, the local proxy dumps the audit event to this remote, append-only, tamper-evident Merkle chain. If the ledger is temporarily offline, execution continues seamlessly using a local durable `queue.db`.
3. **The Zero-Trust Verification Portal:** A completely offline, static HTML interface (`verifier.html`). It allows auditors to paste a cryptographic bundle and an "Expected Anchor," executing a 100% client-side verification of the Ed25519 signature chain to prove a mathematically undeniable chain of custody.

## How we built it
**The Interceptor (Rust):** We built a high-performance daemon utilizing Rust's `tokio` asynchronous runtime to intercept parent `stdin` and child `stdout` streams, parsing JSON-RPC traffic on the fly.
**The Attestation Ledger (Python/FastAPI):** We built a remote clearinghouse that utilizes SQLite `WAL` mode with explicit `BEGIN EXCLUSIVE` locks to handle high-throughput AI swarms while maintaining strict linear chain consistency.
**AI Integration (Codex & GPT-5.6):** As required by the hackathon, we deeply integrated OpenAI's Codex as our primary agentic coding system to architect the complex Rust async interception and FastAPI crypto handshakes. We heavily utilized the GPT-5.6 Terra and Sol models to refine our zero-trust architecture and power the dynamic semantic analysis required for the parameter-aware policy engine.

**The Cryptographic Seal (The Math):**
To prevent the "Garbage-In, Crypto-Out" oracle problem, we use dual Ed25519 PKI signatures and a linear hash chain.
For an intercepted payload `P`, the local daemon generates a device signature:
```text
h_local = SHA-256( PayloadHash || LocalTimestamp || DeviceID || Nonce || AgentID || Status )
Sig_device = Sign_Ed25519( h_local, Key_Device_Private )
```
The remote ledger receives this, links it to the previous event, and returns a cryptographic receipt:
```text
ChainHash = SHA-256( PreviousHash || h_local || LedgerTimestamp )
Receipt = Sign_Ed25519( ... || ChainHash, Key_Ledger_Private )
```

## Challenges we ran into
**The Oracle Problem:** Originally, we planned to build AgentWitness as a simple Python SDK. However, if the logger runs inside the application code, a hallucinating agent could simply alter the data before handing it to the SDK. This forced us to pivot to a much harder OS-level interception architecture using Rust standard I/O proxying.

**The "Audit Illusion" (Red Teaming our own architecture):** Midway through development, we aggressively red-teamed our own architecture and discovered two critical flaws in standard logging approaches: chain truncation attacks (an attacker silently deleting the last 5 rows of a log) and delimiter injection. To combat this, we completely refactored the system. We implemented strict Pydantic regex hardening (`^[a-zA-Z0-9_\-]+$`) and decoupled the verification logic into an air-gapped portal that enforces a strict "Expected Anchor" check, providing true tamper-evidence instead of just trusting the backend.

## Accomplishments that we're proud of
* **Architecting an Unbreakable Cryptographic Chain:** We built a deeply strict, fail-closed architecture that handles concurrency securely without dropping events, forcing the model output into mathematically constrained cryptographic chains.
* **The Zero-Latency Firewall:** Most safety tools put a network gate in front of every action, killing production usability. By utilizing short-lived cryptographic TTL Leases and local asynchronous durable queues, we bounded the destructive blast radius of autonomous agents without introducing network latency.
* **The "Mic-Drop" Verification Demo:** Building an entirely offline, zero-dependency HTML portal that recalculates Merkle chains and Ed25519 signatures locally, flashing a massive red warning if even a single byte is tampered with.

## What we learned
We learned that **Endpoint Protocol Neutrality** is a massive, defensible moat. Big Tech companies are structurally incentivized to only build security logs for their own walled gardens. By building an agnostic OS-level daemon, we learned that independent developers can provide a level of cross-vendor trust and liability that cloud providers simply cannot replicate over a weekend sprint.

## What's next for AgentWitness
Right now, AgentWitness features a highly capable parameter-aware policy engine that defaults to deny. The next evolution is pushing this to the absolute limit. 

We plan to integrate live WebAssembly (Wasm) sandboxing directly into the Rust proxy. This will allow organizations to dynamically push complex, proprietary semantic analysis scripts directly to the edge (where the agent runs), actively terminating the stdio pipe based on real-time heuristic evaluations before any damage is done. We also plan to integrate OpenTimestamps to natively anchor the final `chain_hash` to the Bitcoin blockchain.
