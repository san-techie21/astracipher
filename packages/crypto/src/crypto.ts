/**
 * AgentPassCrypto - High-level crypto API
 *
 * This is the main entry point for all cryptographic operations.
 * Wraps KeyManager, Signer, and KEM into a simple unified API.
 */

import { KeyManager, type HybridKeyPair, type KeyPair } from './key-manager.js';
import { Signer, type SignatureResult, type VerifyResult } from './signer.js';
import { KEM, type EncapsulationResult } from './kem.js';
import { type CryptoConfig, type CryptoMode, DEFAULT_CONFIG } from './types.js';

export class AgentPassCrypto {
  private keyManager: KeyManager;
  private config: CryptoConfig;

  constructor(config: Partial<CryptoConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.keyManager = new KeyManager(this.config);
  }

  /**
   * Generate a new identity key pair for an agent
   */
  async generateIdentityKeys(): Promise<HybridKeyPair | KeyPair> {
    return this.keyManager.generateKeyPair();
  }

  /**
   * Generate a new KEM key pair for encrypted communication
   */
  async generateKEMKeys(): Promise<KeyPair> {
    return this.keyManager.generateKEMKeyPair();
  }

  /**
   * Sign arbitrary data (e.g., a DID document or credential)
   */
  async sign(
    data: string | Uint8Array,
    keys: HybridKeyPair | KeyPair
  ): Promise<SignatureResult> {
    const message =
      typeof data === 'string' ? new TextEncoder().encode(data) : data;

    if ('pqc' in keys && 'classical' in keys) {
      // Hybrid key pair
      return Signer.signHybrid(message, keys as HybridKeyPair);
    } else {
      // Single key pair (PQC only)
      return Signer.signPQCOnly(message, keys as KeyPair);
    }
  }

  /**
   * Verify a signature against public keys
   */
  async verify(
    data: string | Uint8Array,
    signature: SignatureResult,
    publicKeys: {
      pqcPublicKey?: Uint8Array;
      classicalPublicKey?: Uint8Array;
    }
  ): Promise<VerifyResult> {
    const message =
      typeof data === 'string' ? new TextEncoder().encode(data) : data;

    return Signer.verify(message, signature, publicKeys);
  }

  /**
   * Sign a JSON object (serializes to canonical JSON first)
   */
  async signJSON(
    obj: Record<string, unknown>,
    keys: HybridKeyPair | KeyPair
  ): Promise<SignatureResult> {
    const canonical = JSON.stringify(obj, Object.keys(obj).sort());
    return this.sign(canonical, keys);
  }

  /**
   * Verify a signature on a JSON object
   */
  async verifyJSON(
    obj: Record<string, unknown>,
    signature: SignatureResult,
    publicKeys: {
      pqcPublicKey?: Uint8Array;
      classicalPublicKey?: Uint8Array;
    }
  ): Promise<VerifyResult> {
    const canonical = JSON.stringify(obj, Object.keys(obj).sort());
    return this.verify(canonical, signature, publicKeys);
  }

  /**
   * Establish an encrypted channel with another agent
   */
  async encapsulate(
    recipientPublicKey: Uint8Array
  ): Promise<EncapsulationResult> {
    return KEM.encapsulate(recipientPublicKey);
  }

  /**
   * Recover shared secret from a received ciphertext
   */
  async decapsulate(ciphertext: string, secretKey: Uint8Array) {
    return KEM.decapsulate(ciphertext, secretKey);
  }

  /**
   * Get the current crypto configuration
   */
  getConfig(): CryptoConfig {
    return { ...this.config };
  }

  /**
   * Get the key manager instance
   */
  getKeyManager(): KeyManager {
    return this.keyManager;
  }
}
