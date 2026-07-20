# AgentWitness v2 Specification: Achieving Nexart.io Parity

## Objective
The objective is to reach full feature parity with Nexart.io by adding their core advantages—Public Verification Portal, Project Bundles, and Decentralized Anchoring—into the AgentWitness architecture, while retaining our unique Irreversibility Firewall feature.

## Feature 1: Public Verification Portal (Zero-Trust)
**Description:** A purely static web interface that allows anyone to cryptographically verify a sealed execution record without running local code or trusting the ledger's server.
**Requirements:**
- A `build_verifier.py` script that generates a standalone `verifier.html`.
- The UI MUST load `@noble/ed25519` and `@noble/hashes` via Data URIs or embedded code.
- Verification logic must happen **100% client-side**.
- The verifier MUST enforce completeness by checking an expected OpenTimestamps anchor hash against the final chain hash.

## Feature 2: Project Bundles (Canonical Audit Trails)
**Description:** A mechanism to export a complete, self-contained, portable file representing an entire agent session.
**Requirements:**
- A Python CLI tool `create_bundle.py`.
- It packages the local `queue.db` into an `.agentwitness_bundle` JSON file.
- It MUST include `"format_version": "1.0"`.
- It MUST explicitly verify signatures against the raw strings (not JSON objects) to avoid canonicalization bugs.
- It MUST perform a local vs. remote divergence check and alert if the ledger equivocated.

## Feature 3: Decentralized Anchoring (OpenTimestamps)
**Description:** A process to anchor the ledger's internal SQLite Merkle root to the Bitcoin blockchain, eliminating the "single point of failure" trust problem.
**Requirements:**
- A script `anchor_ledger.py` that extracts the `chain_hash` of the latest event in the remote ledger.
- It MUST use the real `opentimestamps-client` to generate an `.ots` proof file.
- This mathematically proves the ledger history existed prior to a specific Bitcoin block.
