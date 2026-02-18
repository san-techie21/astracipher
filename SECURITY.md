# Security Policy

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in AstraCipher, please report it responsibly:

**Email:** [security@astracipher.com](mailto:security@astracipher.com)

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

| Action | Timeframe |
|--------|-----------|
| Acknowledgment of report | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Depends on severity |
| Public disclosure | After fix is released |

## Scope

The following are in scope for security reports:

- **`@astracipher/crypto`** — Post-quantum cryptographic operations (ML-DSA-65, ECDSA P-256, ML-KEM-768)
- **`@astracipher/core`** — DID management, credential issuance/verification, trust chain validation
- **`@astracipher/cli`** — Key generation, credential handling
- **`@astracipher/mcp-server`** — MCP tool security
- **`@astracipher/a2a-adapter`** — A2A protocol authentication

## Out of Scope

- The project website (astracipher.com)
- Third-party dependencies (report to their maintainers directly)
- Social engineering attacks
- Denial of service attacks

## Cryptographic Implementation

AstraCipher uses audited cryptographic libraries:
- [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) — ML-DSA-65, ML-KEM-768
- [`@noble/curves`](https://github.com/paulmillr/noble-curves) — ECDSA P-256

**Note:** While the underlying cryptographic primitives are independently audited, the AstraCipher protocol implementation wrapping them has not yet undergone a formal third-party security audit. This is planned before v1.0 release.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

## Security Best Practices for Users

- Keep your private keys secure — never commit them to version control
- Use the hybrid signature mode (both PQC + classical) for maximum security
- Rotate agent credentials regularly (recommended: every 90 days)
- Monitor your audit trail for unauthorized DID operations
- Use environment variables for API keys, never hardcode them
