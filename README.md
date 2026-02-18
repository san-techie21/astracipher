# AgentPass

**Cryptographic Identity & Trust Protocol for AI Agents**

> The "SSL certificates" for the AI agent economy. Open-source protocol that gives every AI agent a verifiable, cryptographic identity.

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue.svg)](https://www.typescriptlang.org/)
[![Post-Quantum](https://img.shields.io/badge/Crypto-Post--Quantum-green.svg)](#cryptography)
[![FIPS 204](https://img.shields.io/badge/FIPS_204-ML--DSA--65-purple.svg)](#cryptography)

---

## The Problem

AI agents are operating across enterprise systems with **zero identity verification**. No one can answer:

- Which agent performed this action?
- Was it authorized?
- Can we prove compliance to regulators?

MCP servers expose powerful tools, but **any agent can call any tool**. There's no authentication, no authorization, no audit trail.

## The Solution

AgentPass is a **W3C-standards-based protocol** that provides:

- **Decentralized Identifiers (DIDs)** --- Unique, cryptographic identity for every agent (`did:agentpass:mainnet:abc123`)
- **Verifiable Credentials** --- Signed attestations of capabilities, permissions, and trust levels
- **Trust Chains** --- Delegated authority with depth limits (Creator -> Authorizer -> Agent -> Sub-agent)
- **Post-Quantum Cryptography** --- ML-DSA-65 + ECDSA P-256 hybrid signatures (FIPS 204 compliant)
- **Compliance Modules** --- Generate regulatory-ready reports for 10+ frameworks worldwide

## Why Now

- **850M+** AI agents expected by 2030 (Gartner)
- **MCP** adopted by Anthropic, OpenAI, Google, Microsoft --- but has **no identity layer**
- **AAIF** (Linux Foundation + Anthropic) defines agent interoperability --- AgentPass provides the missing identity primitive
- **EU AI Act** enforcement begins 2025-2026, requiring traceability for high-risk AI systems
- **NIST AI RMF** and **ISO 42001** becoming enterprise prerequisites

## Quick Start

### CLI

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
```

### SDK (TypeScript)

```typescript
import { AgentPassClient } from '@agentpass/core';
import { HybridKeyManager } from '@agentpass/crypto';

const keyManager = new HybridKeyManager();
const keyPair = await keyManager.generateKeyPair('hybrid');

const client = new AgentPassClient({ keyManager });
const did = await client.createDID('my-agent', keyPair);
const credential = await client.issueCredential(did, {
  capabilities: ['read', 'write'],
  trustLevel: 8,
});
const result = await client.verifyCredential(credential);
```

### MCP Integration

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
- `create_agent_identity` --- Create a DID for an agent
- `verify_agent` --- Verify an agent's credential
- `check_permissions` --- Check agent permissions for a resource
- `inspect_credential` --- View credential details

## Architecture

```
+----------------------------------------------------------+
|                    AgentPass Protocol                     |
+---------------+----------------+-------------------------+
|  @agentpass/  |  @agentpass/   |  @agentpass/            |
|    crypto     |     core       |   compliance-*          |
|  (PQC keys,   |  (DIDs, VCs,   |  (DPDP, EU AI Act,     |
|   signing)    |  trust chain)  |   GDPR, SEBI, ...)     |
+---------------+----------------+-------------------------+
|                   Integration Layer                       |
|  +--------------+  +-------------+  +------------------+ |
|  | MCP Server   |  | A2A Adapter |  |   REST API       | |
|  | (AI agents)  |  | (Google A2A)|  |   (server)       | |
|  +--------------+  +-------------+  +------------------+ |
+----------------------------------------------------------+
```

## Packages

### Core Protocol (BSL 1.1 --- Open Source)

| Package | Description | Status |
|---------|-------------|--------|
| `@agentpass/crypto` | Post-quantum cryptographic primitives (ML-DSA-65, ML-KEM-768, ECDSA P-256, hybrid) | Core |
| `@agentpass/core` | DID management, credential issuance/verification, trust chains | Core |
| `@agentpass/cli` | Command-line interface for all AgentPass operations | Core |
| `@agentpass/compliance-core` | Pluggable compliance engine for regulatory frameworks | Core |
| `@agentpass/sdk-python` | Python SDK for AgentPass protocol | Core |

### Integrations (BSL 1.1)

| Package | Description |
|---------|-------------|
| `@agentpass/mcp-server` | MCP integration --- expose AgentPass as AI agent tools |
| `@agentpass/a2a-adapter` | Google A2A protocol adapter for agent-to-agent auth |

### Platform & Premium Modules (Proprietary --- [agentpass-platform](https://github.com/AstraFintechLabs/agentpass-platform))

| Component | Description |
|-----------|-------------|
| `@agentpass/server` | Production verification server (PostgreSQL, org management, API keys) |
| `@agentpass/dashboard` | React dashboard for agent identity management |
| 10 compliance modules | DPDP, SEBI, RBI, EU AI Act, GDPR, HIPAA, NIST, SOC 2, ISO 42001, UK AI Safety |

## Cryptography

AgentPass uses **hybrid post-quantum + classical cryptography** by default:

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| ML-DSA-65 | FIPS 204 | Post-quantum digital signatures |
| ECDSA P-256 | FIPS 186-5 | Classical digital signatures |
| ML-KEM-768 | FIPS 203 | Post-quantum key encapsulation |
| Hybrid Mode | --- | Both PQC + classical must validate |

Built on audited libraries: `@noble/post-quantum` and `@noble/curves`.

**Why hybrid?** Classical ECDSA provides battle-tested security today. ML-DSA protects against quantum attacks. Both must validate --- so you get defense-in-depth against both classical and quantum adversaries.

## Competitive Positioning

| | AgentPass | Keycard (a16z) | Aembit | Microsoft Entra Agent ID |
|---|---|---|---|---|
| **Open source** | BSL 1.1 | Closed | Closed | Closed |
| **Post-quantum crypto** | ML-DSA + ECDSA hybrid | No | No | No |
| **W3C DID standard** | Yes | No | No | Partial |
| **MCP native** | Yes | Yes | No | No |
| **Compliance modules** | 10+ frameworks | No | No | No |
| **Self-hosted option** | Yes | No | No | No |
| **Vendor lock-in** | None | Platform | Platform | Azure |

## Development

```bash
# Clone the repo
git clone https://github.com/AstraFintechLabs/agentpass.git
cd agentpass

# Install dependencies
npm install

# Build all packages
npx turbo build

# Run tests
npx turbo test

# Run the CLI locally
npx ts-node packages/cli/src/index.ts --help
```

## Project Structure

```
agentpass/                         # Public repo (BSL 1.1)
+-- packages/
|   +-- crypto/                    # PQC crypto primitives (ML-DSA, ML-KEM, ECDSA)
|   +-- core/                      # Protocol implementation (DIDs, VCs, trust chains)
|   +-- cli/                       # CLI tool
|   +-- sdk-python/                # Python SDK
|   +-- compliance-core/           # Compliance engine framework
+-- integrations/
|   +-- mcp-server/                # MCP integration
|   +-- a2a-adapter/               # Google A2A adapter
+-- e2e-test.mjs                   # E2E test suite (67 tests)
+-- .github/workflows/             # CI/CD pipeline
```

> The production server, dashboard, and premium compliance modules (DPDP, SEBI, RBI, EU AI Act, GDPR, HIPAA, NIST, SOC 2, ISO 42001, UK AI Safety) are in the private [agentpass-platform](https://github.com/AstraFintechLabs/agentpass-platform) repository.

## License

**Business Source License 1.1** (BSL 1.1)

- **Use**: Free to use, modify, and self-host for any purpose
- **Restriction**: Cannot create a competing hosted agent identity/compliance service
- **Change Date**: February 18, 2030 (converts to Apache License 2.0)
- **Full text**: [LICENSE](LICENSE)

This means: startups, enterprises, and developers can freely use AgentPass in their products. The only restriction is you can't take this code and launch a competing AgentPass-as-a-Service offering.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Built by

**Astra Fintech Labs** --- Building trust infrastructure for the AI agent economy.

---

*AgentPass: Because in a world of autonomous AI agents, identity isn't optional.*
