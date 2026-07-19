<div align="center">

# 🛡️ Autonomous Agent AccountabilityMCP

**Kernel-level security daemon for Model Context Protocol**

*Intercepts stdio JSON-RPC • Enforces OS-level sandboxing • Blocks prompt-injection exfiltration*

[![CI](https://github.com/yogami/autonomous-agent-accountability/actions/workflows/ci.yml/badge.svg)](https://github.com/yogami/autonomous-agent-accountability/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## The Problem: The stdio Security Crisis

Anthropic's **Model Context Protocol (MCP)** has become the standard for connecting LLMs to local tools. Most integrations (Cursor, Claude Desktop, CLI runtimes) use **stdio transport** — launching tool servers as subprocesses and piping JSON-RPC over `stdin`/`stdout`.

Because stdio doesn't traverse the network stack, **traditional firewalls and API gateways are completely blind to it**. A prompt-injected agent can:

1. Read `~/.ssh/id_rsa` via a filesystem MCP server
2. POST the contents to `evil-webhook.com` via a network MCP server
3. All of this happens invisibly through subprocess pipes

## The Solution

Autonomous Agent AccountabilityMCP wraps any stdio MCP server with **OS-level sandboxing**:

```
┌─────────────────┐    stdio    ┌──────────────┐    stdio    ┌────────────────┐
│   MCP Client    │◄──────────►│   Autonomous Agent AccountabilityMCP   │◄──────────►│  MCP Server    │
│ (Cursor/Claude) │            │   (Wrapper)  │            │  (Subprocess)  │
└─────────────────┘            └──────┬───────┘            └───────┬────────┘
                                      │                            │
                               Policy Engine              OS Sandbox Enforced
                               JSON-RPC Intercept         ├─ macOS: sandbox-exec
                               Audit Logging              ├─ Linux: Landlock LSM
                                                          └─ Linux: seccomp-BPF
```

## Quick Start

```bash
# Install
cargo install autonomous-agent-accountability

# Wrap an MCP filesystem server with read-only access to /workspace
autonomous-agent-accountability --allow-read '/workspace/*' --deny-net-all -- \
  npx @modelcontextprotocol/server-filesystem /workspace

# Use a policy file
autonomous-agent-accountability --policy policies/filesystem.json -- \
  npx @modelcontextprotocol/server-filesystem /workspace
```

## License

MIT — see [LICENSE](LICENSE) for details.
