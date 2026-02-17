# AgentPass

**Cryptographic Identity & Trust Protocol for AI Agents**

> The "SSL certificates" for the AI agent economy. Open-source protocol that gives every AI agent a verifiable, cryptographic identity.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue.svg)](https://www.typescriptlang.org/)
[![Post-Quantum](https://img.shields.io/badge/Crypto-Post--Quantum-green.svg)](#cryptography)

---

## The Problem

AI agents are operating across enterprise systems with **zero identity verification**. No one can answer:

- Which agent performed this action?
- Was it authorized?
- Can we prove compliance to regulators?

MCP servers expose powerful tools, but **any agent can call any tool**. There's no authentication, no authorization, no audit trail.

## The Solution

AgentPass is a **W3C-standards-based protocol** that provides:

- **Decentralized Identifiers (DIDs)** — Unique, cryptographic identity for every agent (`did:agentpass:mainnet:abc123`)
- **Verifiable Credentials** — Signed attestations of capabilities, permissions, and trust levels
- **Trust Chains** — Delegated authority with depth limits (Creator → Authorizer → Agent → Sub-agent)
- **Post-Quantum Cryptography** — ML-DSA-65 + ECDSA P-256 hybrid signatures (FIPS 204 compliant)
- **Compliance Modules** — Generate regulatory-ready reports for DPDP, EU AI Act, GDPR, and more

## Quick Start

```bash
# Install the CLI
npm install -g @agentpass/cli

# Initialize AgentPass in your project
agentpass init

# Generate post-quantum key pair
agentpass keygen --algo hybrid

# Create an agent identity (DID)
agentpass create --name "my-data-agent" --key .agentpass/keys/agent.pub.json

# Issue a credential
agentpass issue \
  --did did:agentpass:testnet:abc123 \
  --capabilities read,write \
  --trust-level 8 \
  --validity 365d

# Verify a credential
agentpass verify --credential ./credential.json

# Scan for security issues
agentpass scan --target .
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    AgentPass Protocol                     │
├──────────────┬───────────────┬───────────────────────────┤
│  @agentpass/ │  @agentpass/  │  @agentpass/              │
│    crypto    │     core      │    compliance-*           │
│  (PQC keys,  │  (DIDs, VCs,  │  (DPDP, EU AI Act,       │
│   signing)   │  trust chain) │   GDPR, SEBI, ...)       │
├──────────────┴───────────────┴───────────────────────────┤
│                   Integration Layer                       │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ MCP Server  │  │  REST API    │  │   Dashboard    │  │
│  │ (AI agents) │  │  (server)    │  │   (React)      │  │
│  └─────────────┘  └──────────────┘  └────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

## Packages

| Package | Description |
|---------|-------------|
| `@agentpass/crypto` | Post-quantum cryptographic primitives (ML-DSA-65, ML-KEM-768, ECDSA P-256, hybrid) |
| `@agentpass/core` | DID management, credential issuance/verification, trust chains |
| `@agentpass/cli` | Command-line interface for all AgentPass operations |
| `@agentpass/server` | Express-based verification server with REST API |
| `@agentpass/compliance-core` | Pluggable compliance engine for regulatory frameworks |
| `@agentpass/compliance-dpdp` | India's DPDP Act 2023 compliance module |
| `@agentpass/dashboard` | React dashboard for agent identity management |
| `@agentpass/mcp-server` | MCP integration — expose AgentPass as AI agent tools |

## Cryptography

AgentPass uses **hybrid post-quantum + classical cryptography** by default:

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| ML-DSA-65 | FIPS 204 | Post-quantum digital signatures |
| ECDSA P-256 | FIPS 186-5 | Classical digital signatures |
| ML-KEM-768 | FIPS 203 | Post-quantum key encapsulation |
| Hybrid Mode | — | Both PQC + classical must validate |

Built on audited libraries: `@noble/post-quantum` and `@noble/curves`.

## MCP Integration

Any MCP-compatible AI agent (Claude, GPT, etc.) can use AgentPass tools:

```json
{
  "mcpServers": {
    "agentpass": {
      "command": "npx",
      "args": ["@agentpass/mcp-server"]
    }
  }
}
```

Available MCP tools:
- `create_agent_identity` — Create a DID for an agent
- `verify_agent` — Verify an agent's credential
- `check_permissions` — Check agent permissions for a resource
- `inspect_credential` — View credential details

## Compliance Modules

AgentPass helps enterprises prove their AI agents comply with regulations. Compliance modules are **optional premium add-ons** — they don't make AgentPass compliant, they help **your organization** generate regulatory-ready reports from AgentPass credential data.

Available modules:
- **DPDP Act 2023** (India) — Consent, purpose limitation, data residency
- **SEBI CSCRF** (India) — Financial sector AI agent compliance
- **RBI Guidelines** (India) — Banking sector requirements
- **EU AI Act** (Europe) — Risk classification, transparency
- **GDPR** (Europe) — Data protection for AI agents
- **HIPAA AI** (USA) — Healthcare AI compliance
- And more...

## Development

```bash
# Clone the repo
git clone https://github.com/AstraFintechLabs/agentpass.git
cd agentpass

# Install dependencies
npm install

# Build all packages
npx turbo build

# Run the server
npm run dev --workspace=@agentpass/server

# Run the dashboard
npm run dev --workspace=@agentpass/dashboard

# Run with Docker
docker compose -f docker/docker-compose.yml up
```

## Project Structure

```
agentpass/
├── packages/
│   ├── crypto/          # PQC crypto primitives
│   ├── core/            # Protocol implementation
│   ├── cli/             # CLI tool
│   ├── server/          # REST API server
│   ├── dashboard/       # React dashboard
│   ├── compliance-core/ # Compliance engine
│   └── compliance-dpdp/ # DPDP module
├── integrations/
│   └── mcp-server/      # MCP integration
├── docker/              # Docker & nginx configs
├── scripts/             # Database init scripts
└── .github/workflows/   # CI/CD pipeline
```

## License

MIT — See [LICENSE](LICENSE) for details.

## Built by

**Astra Fintech Labs** — Building trust infrastructure for the AI agent economy.

---

*AgentPass: Because in a world of autonomous AI agents, identity isn't optional.*
