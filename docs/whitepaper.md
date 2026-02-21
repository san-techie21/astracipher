# AstraCipher Protocol: Cryptographic Identity for AI Agents

**Version 0.1.0 — February 2026**
**Author:** Santosh T (https://www.linkedin.com/in/santechie21)

---

## Abstract

The proliferation of autonomous AI agents — now exceeding 3 million active deployments in the US and UK alone — has created an identity crisis in software systems. Unlike human users, AI agents lack standardized mechanisms for proving who they are, what they are authorized to do, and who is accountable for their actions. Current approaches rely on API keys and bearer tokens — credentials designed for human-initiated sessions, not autonomous multi-agent systems operating at machine speed.

AstraCipher is an open-source protocol that provides every AI agent with a verifiable, quantum-safe cryptographic identity. Built on W3C Decentralized Identifiers (DIDs), W3C Verifiable Credentials, and NIST-standardized post-quantum cryptography (FIPS 203/204), the protocol enables:

1. **Agent identity** — globally unique, self-sovereign DIDs with hybrid post-quantum signing
2. **Capability-bounded authorization** — verifiable credentials that define exactly what an agent can do
3. **Delegated trust** — cryptographic trust chains from human sponsors to autonomous sub-agents
4. **Offline verification** — credential verification without contacting a central authority

This paper describes the protocol architecture, cryptographic design, trust model, and compliance framework.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Problem Statement](#2-problem-statement)
3. [Protocol Architecture](#3-protocol-architecture)
4. [Cryptographic Design](#4-cryptographic-design)
5. [Decentralized Identifiers for Agents](#5-decentralized-identifiers-for-agents)
6. [Verifiable Credentials](#6-verifiable-credentials)
7. [Trust Chain Model](#7-trust-chain-model)
8. [Threat Model and Security Analysis](#8-threat-model-and-security-analysis)
9. [Protocol Integration (MCP, A2A)](#9-protocol-integration)
10. [Regulatory Compliance](#10-regulatory-compliance)
11. [Implementation and Performance](#11-implementation-and-performance)
12. [Related Work](#12-related-work)
13. [Future Work](#13-future-work)
14. [References](#14-references)

---

## 1. Introduction

### 1.1 The Agent Economy

The year 2025-2026 marks a transition from AI assistants — models that respond to human prompts — to AI agents: autonomous systems that plan, execute, and delegate tasks across organizational boundaries. Gartner predicts that by 2028, 33% of enterprise software applications will include agentic AI, up from less than 1% in 2024.

This transition creates a fundamental identity problem. When a human uses an API, the identity chain is clear: the human authenticates, obtains a session token, and the API trusts the token. When an AI agent acts autonomously — spawning sub-agents, calling external APIs, modifying data — the identity chain breaks:

- **Who is this agent?** There is no standardized way for an agent to prove its identity.
- **What can it do?** Bearer tokens grant binary access (all or nothing), with no fine-grained capability boundaries.
- **Who authorized it?** When an agent spawns a sub-agent, there is no cryptographic proof of the delegation chain back to a human sponsor.
- **Can we audit it?** Without identity, agent actions cannot be attributed or traced.

### 1.2 Why Existing Solutions Fail

Current identity mechanisms are designed for human-initiated, session-based interactions:

| Mechanism | Limitation for Agents |
|---|---|
| API Keys | Static shared secrets; no identity, no capability boundaries |
| OAuth 2.0 | Requires human-in-the-loop for consent; short-lived tokens need refresh |
| mTLS | Certificate-based but no capability model; cumbersome rotation |
| JWT | Issuer-dependent verification; no post-quantum resistance |
| SPIFFE/SPIRE | Workload identity, not agent identity; no credential model |

None of these provide the combination of: (a) autonomous agent identity, (b) capability-bounded authorization, (c) delegated trust chains, and (d) post-quantum cryptographic security.

### 1.3 AstraCipher Approach

AstraCipher addresses this gap with a layered protocol:

```
┌─────────────────────────────────────────────────┐
│             Application Layer                    │
│  MCP Server · A2A Adapter · CLI · REST API      │
├─────────────────────────────────────────────────┤
│             Trust Layer                          │
│  Trust Chains · Delegation · Revocation         │
├─────────────────────────────────────────────────┤
│             Credential Layer                     │
│  Verifiable Credentials · Capabilities ·        │
│  Permissions · Rate Limits                      │
├─────────────────────────────────────────────────┤
│             Identity Layer                       │
│  W3C DIDs · DID Documents · Key Management      │
├─────────────────────────────────────────────────┤
│             Cryptographic Layer                  │
│  ML-DSA-65 · ML-KEM-768 · ECDSA P-256 ·       │
│  Hybrid Signatures · HKDF · SHA-256            │
└─────────────────────────────────────────────────┘
```

---

## 2. Problem Statement

### 2.1 Scale of the Identity Gap

According to the Gravitee State of AI Agent Security Report (2026):

- **3 million** AI agents are active in the US and UK, with 1.5 million running without oversight
- **88%** of organizations report confirmed or suspected AI agent security incidents
- **44%** still authenticate agents using static API keys
- **Only 22%** of teams treat agents as independent, identity-bearing entities

OWASP's Top 10 for Agentic Applications (December 2025) ranked **Agent Identity & Privilege Abuse (ASI03)** as the #3 risk, describing it as: *"Agents operating with excessive permissions, impersonating other agents, or escalating privileges without proper identity verification."*

### 2.2 Threat Landscape

The absence of agent identity enables several attack vectors:

1. **Agent impersonation** — An adversary creates a rogue agent that claims to be a trusted service. Without cryptographic identity, the receiving system has no way to verify the claim.

2. **Privilege escalation** — Agents authenticated with static API keys inherit the full permissions of the key, regardless of the agent's intended scope.

3. **Unauthorized delegation** — An agent spawns sub-agents that inherit its full permissions, creating an unbounded blast radius. A single compromised agent can poison 87% of downstream decisions within 4 hours (Gravitee, 2026).

4. **Accountability gap** — Without identity, agent actions cannot be traced back to a responsible human or organization. Only 28% of organizations can trace agent actions back to a human sponsor.

5. **Quantum harvest attacks** — Nation-state adversaries are recording encrypted agent communications today for future decryption with quantum computers ("harvest now, decrypt later"). Classical-only signatures will be retroactively forgeable.

### 2.3 Design Requirements

Based on this threat landscape, we define the following requirements for an agent identity protocol:

| Requirement | Description |
|---|---|
| **R1: Self-sovereign identity** | Agents must have globally unique identifiers that do not depend on a central authority |
| **R2: Cryptographic authentication** | Identity claims must be provable via digital signatures |
| **R3: Capability bounding** | Credentials must define specific capabilities and permissions |
| **R4: Delegated trust** | Trust must be delegable with monotonically decreasing permissions |
| **R5: Offline verification** | Credentials must be verifiable without contacting the issuer |
| **R6: Quantum resistance** | Cryptographic primitives must resist quantum computer attacks |
| **R7: Auditability** | All agent actions must be traceable to a verified identity |
| **R8: Interoperability** | The protocol must integrate with existing agent frameworks (MCP, A2A) |

---

## 3. Protocol Architecture

### 3.1 System Model

The AstraCipher protocol defines four roles:

- **Creator** — The root of trust, typically a human or organization. Creates the initial trust anchor.
- **Authorizer** — An entity (human or agent) that issues credentials and delegates trust. Must itself have a valid trust chain.
- **Agent** — An autonomous AI agent with a DID and one or more credentials. Can act within the bounds of its credentials.
- **Sub-agent** — An agent spawned by another agent, with strictly fewer permissions. The delegation depth is bounded.

### 3.2 Protocol Flow

A typical agent lifecycle follows this flow:

```
1. IDENTITY:   Creator generates hybrid keypair → creates DID document
2. CREDENTIAL: Authorizer issues verifiable credential → defines capabilities
3. DELEGATION: Agent delegates to sub-agent → trust chain extends
4. ACTION:     Agent presents credential → verifier checks offline
5. AUDIT:      Action logged with DID → cryptographic audit trail
6. REVOCATION: Creator/Authorizer revokes credential → agent loses access
```

### 3.3 Network Model

AstraCipher supports three network modes:

- **Mainnet** — Production identities with persistent DID registry
- **Testnet** — Development and testing with ephemeral identities
- **Local** — Fully offline operation for air-gapped environments

The DID method is `did:astracipher:<network>:<unique-id>`.

---

## 4. Cryptographic Design

### 4.1 Algorithm Selection

AstraCipher uses NIST-standardized post-quantum algorithms in hybrid mode:

| Function | Algorithm | Standard | Security Level |
|---|---|---|---|
| Digital signatures (PQC) | ML-DSA-65 | FIPS 204 | NIST Level 3 (AES-192 equivalent) |
| Digital signatures (Classical) | ECDSA P-256 | FIPS 186-5 | 128-bit classical |
| Key encapsulation | ML-KEM-768 | FIPS 203 | NIST Level 3 |
| Hashing | SHA-256 | FIPS 180-4 | 128-bit |
| Key derivation | HKDF-SHA-256 | RFC 5869 | 128-bit |

### 4.2 Hybrid Signature Scheme

The protocol uses a hybrid signature scheme that combines ML-DSA-65 and ECDSA P-256. Both signatures must verify for the overall verification to succeed.

```
HybridSign(message, hybridKey):
  1. canonicalMsg = CanonicalJSON(message)
  2. msgBytes = UTF8Encode(canonicalMsg)
  3. pqcSig = ML-DSA-65.Sign(hybridKey.pqc.secretKey, msgBytes)
  4. msgHash = SHA-256(msgBytes)
  5. classicalSig = ECDSA-P256.Sign(hybridKey.classical.secretKey, msgHash)
  6. return { pqcSignature, classicalSignature, timestamp, messageHash }

HybridVerify(message, signature, publicKeys):
  1. Check signature freshness (< 24 hours by default)
  2. canonicalMsg = CanonicalJSON(message)
  3. msgBytes = UTF8Encode(canonicalMsg)
  4. pqcValid = ML-DSA-65.Verify(publicKeys.pqc, msgBytes, signature.pqc)
  5. msgHash = SHA-256(msgBytes)
  6. classicalValid = ECDSA-P256.Verify(publicKeys.classical, msgHash, signature.classical)
  7. return pqcValid AND classicalValid
```

**Rationale for hybrid mode:** The hybrid approach provides defense in depth during the post-quantum transition period. If either algorithm is broken, the other still provides security. This aligns with NIST SP 800-227 recommendations and the CNSA 2.0 timeline requiring post-quantum compliance for national security systems by January 2027.

### 4.3 Canonical JSON

All JSON data is canonicalized before signing to ensure deterministic serialization:

1. Object keys are sorted lexicographically
2. No trailing commas or whitespace
3. Numbers are represented without leading zeros
4. Dates are ISO 8601 strings
5. Undefined/null values are omitted

### 4.4 Key Sizes

| Key Type | Public Key | Secret Key | Signature |
|---|---|---|---|
| ML-DSA-65 | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| ECDSA P-256 | 33 bytes | 32 bytes | 64 bytes |
| ML-KEM-768 | 1,184 bytes | 2,400 bytes | N/A |

### 4.5 Signature Freshness

Signatures include a timestamp and are rejected if older than a configurable threshold (default: 24 hours). This prevents replay attacks with stale signatures while allowing sufficient time for asynchronous operations.

---

## 5. Decentralized Identifiers for Agents

### 5.1 DID Method: `did:astracipher`

Each agent identity is a W3C DID conforming to the DID Core specification (W3C Recommendation, July 2022). The DID method is:

```
did:astracipher:<network>:<unique-id>

Examples:
  did:astracipher:mainnet:c2e3d421c83a3cbe7faf6738
  did:astracipher:testnet:48ead5c80fd55b31ee2d354f
```

The unique ID is derived from the SHA-256 hash of the combined public key material.

### 5.2 DID Document Structure

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://astracipher.com/ns/v1"
  ],
  "id": "did:astracipher:testnet:c2e3d421c83a3cbe",
  "controller": "did:astracipher:testnet:c2e3d421c83a3cbe",
  "verificationMethod": [
    {
      "id": "did:astracipher:testnet:c2e3d421c83a3cbe#key-pqc-1",
      "type": "ML-DSA-65-2024",
      "controller": "did:astracipher:testnet:c2e3d421c83a3cbe",
      "publicKeyMultibase": "u<base64url-encoded-public-key>"
    },
    {
      "id": "did:astracipher:testnet:c2e3d421c83a3cbe#key-classical-1",
      "type": "EcdsaSecp256r1VerificationKey2019",
      "controller": "did:astracipher:testnet:c2e3d421c83a3cbe",
      "publicKeyMultibase": "u<base64url-encoded-public-key>"
    }
  ],
  "authentication": ["...#key-pqc-1", "...#key-classical-1"],
  "assertionMethod": ["...#key-pqc-1", "...#key-classical-1"],
  "service": [],
  "created": "2026-02-19T08:54:17.048Z",
  "updated": "2026-02-19T08:54:17.048Z",
  "proof": { /* hybrid signature over the document */ }
}
```

### 5.3 DID Operations

| Operation | Description |
|---|---|
| **Create** | Generate hybrid keypair, construct DID document, self-sign |
| **Resolve** | Look up DID document from registry or cache |
| **Verify** | Verify the DID document's self-signature |
| **Update** | Modify service endpoints or add verification methods (signed by controller) |
| **Deactivate** | Mark DID as revoked (signed by controller) |

---

## 6. Verifiable Credentials

### 6.1 Agent Identity Credential

An Agent Identity Credential is a W3C Verifiable Credential that binds an agent's DID to a set of capabilities, permissions, and constraints.

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://astracipher.com/credentials/v1"],
  "type": ["VerifiableCredential", "AgentIdentityCredential"],
  "issuer": "did:astracipher:testnet:<issuer-id>",
  "credentialSubject": {
    "id": "did:astracipher:testnet:<agent-id>",
    "name": "trading-bot-alpha",
    "capabilities": ["market-data:read", "orders:execute"],
    "permissions": [
      { "resource": "equity/*", "actions": ["read", "execute"] }
    ],
    "trustLevel": 7,
    "rateLimits": { "requestsPerMinute": 100 }
  },
  "proof": { /* hybrid signature by issuer */ }
}
```

### 6.2 Capability Model

Capabilities are coarse-grained labels (e.g., `market-data:read`). Permissions are fine-grained resource-action pairs with glob pattern matching:

- `equity/*` matches `equity/RELIANCE`, `equity/TCS`, etc.
- `api/*/users` matches `api/v1/users`, `api/v2/users`, etc.
- Exact match: `admin/settings` only matches `admin/settings`

### 6.3 Trust Levels

Trust levels range from 1 (minimal) to 10 (maximum). They are advisory and can be used by verifiers to make risk-based decisions.

### 6.4 Credential Constraints

- Maximum validity: 5 years (prevents indefinite credentials)
- Nonce: Each credential includes a unique nonce for replay protection
- Expiration: ISO 8601 timestamp; verification fails after expiration

---

## 7. Trust Chain Model

### 7.1 Chain Structure

A trust chain is an ordered sequence of links from a trust root to a leaf agent:

```
Creator (depth 0) → Authorizer (depth 1) → Agent (depth 2) → Sub-agent (depth 3)
```

### 7.2 Monotonic Capability Reduction

Each link in the trust chain can only have equal or fewer capabilities than its parent. This is enforced by intersecting capabilities at each delegation step:

```
Parent capabilities:  [read, write, execute, admin]
Child capabilities:   [read, execute]
Effective at child:   [read, execute]  (intersection)
```

### 7.3 Delegation Depth Limits

The maximum delegation depth is configurable (default: 5). Each link's `maxDelegationDepth` is monotonically decreasing, preventing unbounded delegation chains.

### 7.4 Chain Verification

Verifying a trust chain requires:

1. The root link has no parent and is self-signed
2. Each subsequent link has a valid authorization signature from its parent
3. Capabilities monotonically decrease
4. Delegation depth limits are respected
5. No credentials are expired or revoked

---

## 8. Threat Model and Security Analysis

### 8.1 Threat Model

We assume the following adversary capabilities:

- **Network adversary:** Can observe, intercept, and modify network traffic
- **Compromised agent:** A single agent in a multi-agent system is compromised
- **Quantum adversary (future):** Has access to a cryptographically relevant quantum computer

### 8.2 Security Properties

| Property | Mechanism |
|---|---|
| **Identity unforgeability** | Hybrid signatures; forging requires breaking both ML-DSA-65 AND ECDSA P-256 |
| **Credential integrity** | Signed by issuer; any modification invalidates the signature |
| **Replay protection** | Nonces and signature freshness checks |
| **Delegation bounding** | Monotonic capability reduction and depth limits |
| **Forward secrecy** | ML-KEM-768 key encapsulation for ephemeral shared secrets |
| **Quantum resistance** | ML-DSA-65 and ML-KEM-768 resist quantum attacks |

### 8.3 Limitations

- **Registry availability:** DID resolution depends on registry availability (mitigated by caching and offline verification with pre-shared keys)
- **Key management:** Agent secret keys must be securely stored; compromised keys require revocation
- **Clock skew:** Signature freshness checks assume reasonably synchronized clocks

---

## 9. Protocol Integration

### 9.1 Model Context Protocol (MCP)

AstraCipher provides an MCP Server that exposes identity operations as tools:

- `create_agent_identity` — Generate a DID with hybrid keys
- `verify_agent_credential` — Verify a credential offline
- `check_agent_permission` — Check if an agent has a specific permission

Any MCP-compatible AI agent (Claude, GPT, etc.) can use these tools to establish and verify identity.

### 9.2 Google Agent-to-Agent (A2A)

The A2A adapter enriches the Agent Card (`.well-known/agent-card.json`) with:

- Agent DID and verification methods
- Trust chain metadata
- Credential-based skill declarations
- Authentication requirements for task submission

---

## 10. Regulatory Compliance

AstraCipher's compliance engine maps agent activity to regulatory requirements:

| Framework | Key Requirement | AstraCipher Mapping |
|---|---|---|
| **EU AI Act** | Traceability and human oversight | Trust chains trace to human creators |
| **DPDP Act (India)** | Data processor accountability | DID-based audit trail per agent |
| **SEBI CSCRF** | Cybersecurity controls for financial data | Capability-bounded access with rate limits |
| **SOC 2** | Access controls and audit logging | Verifiable credentials + signed audit logs |
| **HIPAA** | PHI access controls | Permission-based resource scoping |
| **GDPR** | Data processing accountability | DID-linked processing records |

---

## 11. Implementation and Performance

### 11.1 SDK Packages

The protocol is implemented as a TypeScript monorepo with the following packages:

| Package | Description | npm |
|---|---|---|
| `@astracipher/crypto` | Post-quantum cryptographic primitives | `@astracipher/crypto` |
| `@astracipher/core` | DID, Credential, Trust Chain management | `@astracipher/core` |
| `@astracipher/cli` | Command-line interface | `@astracipher/cli` |
| `@astracipher/compliance-core` | Regulatory compliance engine | `@astracipher/compliance-core` |
| `@astracipher/mcp-server` | MCP protocol integration | `@astracipher/mcp-server` |
| `@astracipher/a2a-adapter` | Google A2A protocol adapter | `@astracipher/a2a-adapter` |

A Python SDK (`astracipher`) provides async client bindings.

### 11.2 Performance Benchmarks

Measured on Apple M2 Pro, Node.js 22:

| Operation | Time |
|---|---|
| ML-DSA-65 key generation | ~15ms |
| ECDSA P-256 key generation | ~1ms |
| Hybrid key generation | ~16ms |
| DID creation (with key gen) | ~100ms |
| Credential issuance (with signing) | ~30ms |
| Credential verification | ~45ms |
| Trust chain verification (4 links) | ~120ms |

All operations run in both Node.js and browser environments using the `@noble/post-quantum` and `@noble/curves` libraries.

---

## 12. Related Work

- **SPIFFE/SPIRE** — Workload identity for microservices. Focuses on infrastructure-level identity, not agent capabilities or trust chains.
- **Teleport Machine ID** — Machine identity with certificate-based auth. Does not provide post-quantum security or credential-based capabilities.
- **CyberArk Machine Identity** — Enterprise secrets management. Centralized model incompatible with decentralized agent ecosystems.
- **DIDComm** — Secure messaging over DIDs. Complementary to AstraCipher; could be used as a transport layer.
- **Veramo** — DID toolkit. Provides DID infrastructure but no agent-specific credential model or trust chains.

---

## 13. Future Work

1. **Formal verification** of the trust chain model using TLA+ or Lean 4
2. **DID resolution protocol** with gossip-based discovery for decentralized networks
3. **Revocation lists** using Merkle-tree accumulators for efficient credential revocation
4. **Multi-party credentials** where multiple issuers co-sign a credential
5. **Threshold signatures** for high-security agent operations
6. **Hardware key storage** integration (TPM, HSM, WebAuthn)
7. **Cross-chain DID anchoring** for tamper-evident identity records

---

## 14. References

1. W3C. "Decentralized Identifiers (DIDs) v1.0." W3C Recommendation, July 2022.
2. W3C. "Verifiable Credentials Data Model v2.0." W3C Recommendation, March 2025.
3. NIST. "FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)." August 2024.
4. NIST. "FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)." August 2024.
5. OWASP. "Top 10 for Agentic Applications." December 2025.
6. Gravitee. "State of AI Agent Security 2026." February 2026.
7. NSA. "CNSA 2.0: Cybersecurity Advisory on Post-Quantum Cryptography." September 2022.
8. Strata Identity / CSA. "The State of Machine (Non-Human) Identity Security." 2026.
9. Gartner. "Predicts 2026: Agentic AI." October 2025.
10. NIST. "AI 600-1: Artificial Intelligence Risk Management Framework: Generative AI Profile." July 2024.

---

*AstraCipher is open-source software under the BSL 1.1 license (converts to Apache 2.0 on February 18, 2030). For more information, visit [astracipher.com](https://astracipher.com).*
