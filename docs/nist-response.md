# Response to NIST NCCoE Concept Paper: Accelerating the Adoption of Software and AI Agent Identity and Authorization

**Submitted to:** AI-Identity@nist.gov
**Date:** February 21, 2026
**Submitted by:** Santosh T, Creator of AstraCipher
**LinkedIn:** https://www.linkedin.com/in/santechie21
**Project Website:** https://astracipher.com
**Open Source Repository:** https://github.com/san-techie21/astracipher

---

## Executive Summary

We appreciate the opportunity to respond to the NCCoE concept paper "Accelerating the Adoption of Software and AI Agent Identity and Authorization." This response draws from our experience building AstraCipher, an open-source protocol and SDK that provides cryptographic identity for AI agents using W3C Decentralized Identifiers (DIDs), W3C Verifiable Credentials, and NIST-standardized post-quantum cryptography (FIPS 203 / FIPS 204).

We offer this response in three parts:

1. **Use cases and real-world challenges** we have observed in the field
2. **Technical recommendations** addressing the specific questions raised in the concept paper
3. **An open-source reference implementation** available for NCCoE lab demonstration

Our central thesis: **AI agents require a fundamentally different identity model than human users or traditional software services.** Bearer tokens, OAuth sessions, and workload identities were designed for human-initiated, session-based interactions. Autonomous agents that plan, delegate, and operate across organizational boundaries require self-sovereign, capability-bounded, cryptographically verifiable identities — with post-quantum resistance built in from the foundation.

---

## 1. Use Cases and Opportunities

### 1.1 Multi-Agent Financial Trading

AI agents in financial services autonomously execute trades, manage portfolios, and interact with multiple broker APIs. In this context:

- **Identity challenge:** A trading agent spawns sub-agents for market analysis, order execution, and risk assessment. Each sub-agent calls external APIs on behalf of the parent. Current approaches issue a single API key or OAuth token to the parent agent, which is then shared with sub-agents — creating a flat, unauditable trust model.
- **What is needed:** Each agent and sub-agent requires its own verifiable identity with a cryptographic chain of delegation back to the human portfolio manager. Credentials must encode capability boundaries (e.g., "can read market data for equity/RELIANCE but cannot execute trades exceeding $10,000").

### 1.2 Healthcare Agent Coordination

AI agents in healthcare coordinate across hospital systems, insurance providers, and pharmacy networks:

- **Identity challenge:** A patient-facing triage agent needs to request lab results from Hospital A, check insurance coverage with Provider B, and schedule a follow-up with Clinic C. Each system needs to verify: (a) the agent's identity, (b) the patient's consent delegation, and (c) the agent's authorized scope — without calling a central identity server that may introduce latency or become a single point of failure.
- **What is needed:** Offline-verifiable credentials containing the agent's identity, delegated consent proof, and fine-grained capability boundaries — verifiable using only the issuer's public key.

### 1.3 MCP and A2A Protocol Ecosystems

The Model Context Protocol (MCP) and Google's Agent2Agent (A2A) protocol are rapidly becoming the standard interfaces for agent communication. Both currently rely on OAuth 2.1 / OpenID Connect for authorization:

- **Identity challenge:** OAuth answers "is this session authorized?" but not "who is this agent, what are its capabilities, and who is accountable for its actions?" When Agent B receives a request from Agent A via A2A, there is no standardized way for Agent B to verify Agent A's identity, capabilities, or delegation chain without calling an external authorization server.
- **What is needed:** A credential-based identity layer that complements OAuth — where agents carry self-describing, cryptographically signed credentials that can be verified offline by any peer.

---

## 2. Responses to Concept Paper Questions

### 2.1 How should agents be recognized in enterprise architectures?

**Recommendation: Treat agents as first-class identity principals with W3C Decentralized Identifiers (DIDs).**

AI agents should not be modeled as extensions of human user accounts or as service accounts. They should receive globally unique, self-sovereign identifiers following the W3C DID specification. Specifically:

- **DID Method:** A purpose-built DID method (e.g., `did:astracipher:mainnet:<fingerprint>`) that encodes the agent's cryptographic public keys directly in the identifier, enabling resolution without a centralized registry.
- **DID Documents:** Each agent's DID Document should contain its verification methods (public keys), supported cryptographic algorithms, and service endpoints — following the W3C DID Core v1.0 specification.
- **Network Segmentation:** The DID method should support network qualifiers (e.g., `testnet`, `mainnet`, `enterprise:<org-id>`) to enable organizational isolation while maintaining global uniqueness.

This approach is aligned with NIST SP 800-63-4 (Digital Identity Guidelines) and extends it to non-human principals.

### 2.2 What metadata is essential for an AI agent's identity?

**Recommendation: Verifiable Credentials that encode capabilities, permissions, trust level, and delegation chain.**

An agent's identity metadata should be carried in a W3C Verifiable Credential containing:

| Metadata Field | Purpose | Example |
|---|---|---|
| `id` | Globally unique credential identifier | `urn:uuid:a3b4c5d6-e7f8-...` |
| `issuer` | DID of the entity that issued the credential | `did:astracipher:mainnet:c2e3d4...` |
| `credentialSubject.id` | DID of the agent | `did:astracipher:mainnet:4bead5...` |
| `credentialSubject.name` | Human-readable agent name | `portfolio-trading-agent` |
| `credentialSubject.capabilities` | Enumerated capabilities | `["market-data:read", "orders:execute"]` |
| `credentialSubject.trustLevel` | Numeric trust score (1-10) | `7` |
| `credentialSubject.permissions` | Fine-grained access rules with glob patterns | `[{"resource": "equity/*", "actions": ["read", "execute"]}]` |
| `issuanceDate` | When the credential was issued | ISO 8601 timestamp |
| `expirationDate` | When the credential expires | ISO 8601 timestamp |
| `proof` | Cryptographic signature(s) | Hybrid PQC + classical signatures |

This credential is self-contained: any verifier with access to the issuer's public key can verify its authenticity, integrity, and expiration — without contacting an external server.

### 2.3 Should agent identities be ephemeral or fixed?

**Recommendation: Support both, with a preference for short-lived credentials on long-lived identities.**

The agent's **DID (identity)** should be persistent — it represents the agent's existence and is tied to its cryptographic key pair. The agent's **Verifiable Credential (authorization)** should be short-lived and task-scoped:

- **Persistent DID:** Created when the agent is provisioned. Survives across tasks and sessions. Revocable by the issuing organization.
- **Short-lived Credentials:** Issued per-task or per-session with explicit `expirationDate` (hours to days). Capability-bounded to the specific task. Automatically invalid after expiry — no revocation infrastructure needed for the common case.

This separation mirrors the human model: a person has a persistent identity (passport) but receives short-lived authorization (boarding pass) for specific actions.

### 2.4 Should identities be tied to hardware, software, or organizational boundaries?

**Recommendation: Organizational boundaries as the primary trust anchor, with software attestation as a secondary signal.**

- **Organization-tied:** An agent's DID should be issued by an organizational DID (e.g., `did:astracipher:mainnet:<org-fingerprint>`) that serves as the root of a trust chain. This enables enterprises to: (a) revoke all agent identities if the organization is compromised, (b) establish bilateral trust between organizations by exchanging organizational DIDs, and (c) audit all agent actions back to the responsible organization.
- **Software attestation (optional):** The credential can include software attestation metadata (runtime, model version, SDK version) as supplementary claims — but the organizational trust anchor should be the primary binding.
- **Hardware binding:** Should be optional and reserved for high-assurance environments. Requiring hardware-bound identity would exclude cloud-based and ephemeral agent deployments.

### 2.5 How should delegation chains be handled?

**Recommendation: Cryptographic trust chains with depth limits and capability attenuation.**

When Agent A (human-sponsored) spawns Sub-Agent B, and Sub-Agent B spawns Sub-Agent C:

```
Human Sponsor → Agent A → Sub-Agent B → Sub-Agent C
     DID_0         DID_1       DID_2         DID_3
```

Each delegation should be recorded as a verifiable credential where:
- The parent's credential is referenced in the child's `proof.verificationMethod`
- Capabilities can only be **attenuated** (narrowed), never expanded — Sub-Agent B cannot grant Sub-Agent C more capabilities than B itself holds
- A configurable **maximum chain depth** prevents unbounded delegation
- Any verifier can walk the chain back to the human sponsor's DID

This is analogous to X.509 certificate chains but purpose-built for agent delegation semantics.

### 2.6 What controls should prevent and mitigate prompt injection?

**Recommendation: Credential-bound capability boundaries as a defense-in-depth layer.**

Prompt injection is an input-layer attack; cryptographic identity is an authorization-layer defense. Together they form defense-in-depth:

- Even if an agent is prompt-injected and attempts to perform unauthorized actions, the **credential's capability boundaries** limit what it can do. A market-data agent with `permissions: [{resource: "equity/*", actions: ["read"]}]` cannot execute trades regardless of what instructions are injected into its prompt.
- **Permission verification at every API boundary:** Each service that receives an agent's request should verify the agent's credential and check that the requested action falls within its declared capabilities.
- **Non-repudiation:** Because every agent action is tied to a cryptographic identity, injected actions can be attributed and audited — even if the injection succeeds at the prompt layer.

### 2.7 What about post-quantum cryptographic readiness?

**Recommendation: Hybrid signatures (PQC + classical) from day one.**

NIST's own FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standards are finalized. Any identity framework standardized in 2026 should mandate post-quantum readiness:

- **Hybrid signing:** Each credential should carry both a post-quantum signature (ML-DSA-65) and a classical signature (ECDSA P-256). Verification requires both to pass. This provides: (a) quantum resistance via ML-DSA, (b) backward compatibility via ECDSA, and (c) defense-in-depth if either algorithm is compromised.
- **Hybrid key encapsulation:** For encrypted agent-to-agent communication, use ML-KEM-768 + ECDH P-256 hybrid key exchange.
- **Rationale:** Agent credentials are long-lived artifacts. Credentials issued today may be verified years from now. "Harvest now, decrypt later" attacks mean classical-only signatures are already insufficient for high-assurance applications.

---

## 3. Reference Implementation: AstraCipher Protocol

We have built and open-sourced a complete implementation of the architecture described above:

### 3.1 Overview

**AstraCipher** is an open-source SDK (BSL 1.1 → Apache 2.0) that provides:

- DID issuance and resolution (`did:astracipher` method)
- Verifiable Credential issuance with hybrid post-quantum signatures
- Capability-bounded authorization with glob-pattern permission matching
- Trust chain management with configurable depth limits and capability attenuation
- MCP Server integration for tool-based identity operations
- A2A Adapter for agent-to-agent identity exchange
- CLI for credential management
- Compliance scoring against OWASP Agentic Top 10 and eIDAS 2.0

### 3.2 Availability

| Package | Registry | Install Command |
|---|---|---|
| `@astracipher/core` | npm | `npm install @astracipher/core` |
| `@astracipher/crypto` | npm | `npm install @astracipher/crypto` |
| `@astracipher/mcp-server` | npm | `npm install @astracipher/mcp-server` |
| `@astracipher/a2a-adapter` | npm | `npm install @astracipher/a2a-adapter` |
| `@astracipher/cli` | npm | `npm install -g @astracipher/cli` |
| `astracipher` | PyPI | `pip install astracipher` |

- **Source code:** https://github.com/san-techie21/astracipher
- **Live demo (browser-based PQC):** https://astracipher.com
- **Protocol whitepaper:** https://astracipher.com/whitepaper

### 3.3 NCCoE Lab Demonstration Offer

We offer AstraCipher as a candidate technology for the proposed NCCoE demonstration project. The SDK is:

- **Open source** and freely available
- **Standards-based** (W3C DID Core, W3C Verifiable Credentials, FIPS 203/204)
- **Interoperable** with MCP and A2A protocols — the two dominant agent communication standards
- **Ready for integration testing** with the other identity frameworks referenced in the concept paper (OAuth 2.1, SPIFFE/SPIRE, SCIM, NGAC)

We are willing to participate in technical collaborations, provide engineering support, and contribute to the NCCoE Practice Guide.

---

## 4. Alignment with Referenced Standards

| NIST Reference | AstraCipher Alignment |
|---|---|
| SP 800-207 (Zero Trust) | Credential verification at every agent boundary; no implicit trust |
| SP 800-63-4 (Digital Identity) | W3C DIDs as non-human identity principals; verifiable credential assurance |
| FIPS 204 (ML-DSA) | ML-DSA-65 hybrid signatures on all credentials |
| FIPS 203 (ML-KEM) | ML-KEM-768 hybrid key encapsulation for agent-to-agent encryption |
| OAuth 2.1 / OpenID Connect | Complementary layer — AstraCipher adds credential-based identity on top of OAuth sessions |
| SPIFFE/SPIRE | AstraCipher DIDs can interoperate with SPIFFE IDs at the workload boundary |
| SCIM | Agent lifecycle events (create, rotate, revoke) can emit SCIM-compatible provisioning events |

---

## 5. Summary of Recommendations

1. **Treat AI agents as first-class identity principals** — not extensions of human accounts or service accounts
2. **Adopt W3C DIDs** as the standard identifier format for agents — enabling decentralized, self-sovereign identity
3. **Use W3C Verifiable Credentials** for capability-bounded authorization metadata — self-contained and offline-verifiable
4. **Separate persistent identity (DID) from short-lived authorization (credential)** — mirroring the passport/boarding-pass model
5. **Mandate hybrid post-quantum signatures** (FIPS 204 ML-DSA + ECDSA) — credentials issued today must remain verifiable in a post-quantum future
6. **Standardize cryptographic delegation chains** — enabling trust traversal from sub-agent back to human sponsor
7. **Leverage credential capability boundaries** as a defense-in-depth layer against prompt injection
8. **Ensure interoperability** with MCP and A2A protocols — the emerging standards for agent communication

---

## Contact Information

**Santosh T**
Creator of AstraCipher
LinkedIn: https://www.linkedin.com/in/santechie21
Website: https://astracipher.com
GitHub: https://github.com/san-techie21/astracipher

We welcome the opportunity to discuss this response further and participate in the NCCoE demonstration project.

---

*AstraCipher is licensed under BSL 1.1, converting to Apache 2.0 on February 18, 2030.*
