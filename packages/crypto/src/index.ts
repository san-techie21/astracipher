/**
 * @agentpass/crypto - Post-Quantum Cryptographic Primitives
 *
 * Provides hybrid cryptographic operations combining:
 * - ML-DSA-65 (FIPS 204) for digital signatures
 * - ML-KEM-768 (FIPS 203) for key encapsulation
 * - ECDSA P-256 as classical fallback (hybrid mode)
 * - SLH-DSA (FIPS 205) as conservative stateless hash-based fallback
 *
 * All operations support hybrid mode (PQC + classical) for defense in depth.
 */

export { AgentPassCrypto } from './crypto.js';
export { KeyManager, type KeyPair, type HybridKeyPair } from './key-manager.js';
export { Signer, type SignatureResult, type VerifyResult } from './signer.js';
export { KEM, type EncapsulationResult } from './kem.js';
export {
  type CryptoAlgorithm,
  type CryptoMode,
  type CryptoConfig,
  DEFAULT_CONFIG,
} from './types.js';
