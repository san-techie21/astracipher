/**
 * @astracipher/core - Core Protocol Implementation
 *
 * The identity and trust layer for AI agents.
 * Implements W3C DID v1.1 and Verifiable Credentials for the agent economy.
 */

// DID operations
export {
  DIDManager,
  type DIDDocument,
  type DIDVerificationMethod,
  type DIDService,
  type DIDManagerOptions,
} from './did/did-manager.js';

// Verifiable Credentials
export {
  CredentialManager,
  type AgentCredential,
  type CredentialSubject,
  type CredentialProof,
  type CredentialStatus,
} from './credentials/credential-manager.js';

// Trust Chain
export {
  TrustChain,
  type TrustChainLink,
  type TrustChainVerification,
} from './trust-chain/trust-chain.js';

// High-level AstraCipher client
export { AstraCipher, type AstraCipherConfig } from './astra-cipher.js';
