/**
 * AstraCipherCrypto - High-level crypto API
 *
 * This is the main entry point for all cryptographic operations.
 * Wraps KeyManager, Signer, and KEM into a simple unified API.
 */

import { KeyManager, type HybridKeyPair, type KeyPair } from './key-manager.js';
import { Signer, type SignatureResult, type VerifyResult } from './signer.js';
import { KEM, type EncapsulationResult } from './kem.js';
import { type CryptoConfig, type CryptoMode, DEFAULT_CONFIG } from './types.js';

export class AstraCipherCrypto {
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
    const canonical = AstraCipherCrypto.canonicalJSON(obj);
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
    const canonical = AstraCipherCrypto.canonicalJSON(obj);
    return this.verify(canonical, signature, publicKeys);
  }

  /**
   * Recursively sort all object keys for deterministic JSON serialization.
   * This ensures signatures cover ALL nested fields, preventing
   * tampering of deeply nested values like credentialSubject.trustLevel.
   *
   * CRIT-7 FIX: Rejects non-JSON-safe values (NaN, Infinity, BigInt, -0, undefined in objects)
   * that could cause cross-platform signature mismatches.
   */
  static canonicalJSON(value: unknown): string {
    const sanitized = AstraCipherCrypto.sortDeep(value, 0);
    return JSON.stringify(sanitized);
  }

  /** Maximum nesting depth to prevent stack overflow attacks */
  private static readonly MAX_DEPTH = 64;

  private static sortDeep(value: unknown, depth: number): unknown {
    // Guard against stack overflow via deeply-nested objects
    if (depth > AstraCipherCrypto.MAX_DEPTH) {
      throw new Error(
        `Canonical JSON nesting depth exceeds ${AstraCipherCrypto.MAX_DEPTH} — possible attack`
      );
    }

    // Primitives
    if (value === null) return null;
    if (value === undefined) return null; // normalize undefined → null for JSON

    if (typeof value === 'number') {
      // Reject non-finite numbers (NaN, Infinity, -Infinity) — not valid JSON
      if (!Number.isFinite(value)) {
        throw new Error(
          `Canonical JSON does not support ${value} — only finite numbers allowed`
        );
      }
      // Normalize -0 → 0 to prevent cross-platform divergence
      if (Object.is(value, -0)) return 0;
      return value;
    }

    if (typeof value === 'bigint') {
      throw new Error(
        'Canonical JSON does not support BigInt — convert to string first'
      );
    }

    if (typeof value === 'string' || typeof value === 'boolean') {
      return value;
    }

    if (typeof value === 'function' || typeof value === 'symbol') {
      throw new Error(
        `Canonical JSON does not support ${typeof value} values`
      );
    }

    if (typeof value !== 'object') {
      return value;
    }

    // Arrays
    if (Array.isArray(value)) {
      return value.map((item) => AstraCipherCrypto.sortDeep(item, depth + 1));
    }

    // Date objects → ISO string for deterministic serialization
    if (value instanceof Date) {
      return value.toISOString();
    }

    // Typed arrays → convert to regular array
    if (ArrayBuffer.isView(value)) {
      return Array.from(value as Uint8Array);
    }

    // Plain objects — sort keys recursively
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      // Skip undefined values in objects (they're omitted in JSON.stringify)
      if (v !== undefined) {
        sorted[key] = AstraCipherCrypto.sortDeep(v, depth + 1);
      }
    }
    return sorted;
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
