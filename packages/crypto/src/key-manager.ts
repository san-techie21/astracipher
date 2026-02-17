/**
 * Key generation and management for AgentPass
 *
 * Supports ML-DSA-65 (post-quantum), ECDSA P-256 (classical),
 * and hybrid mode combining both.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import {
  type CryptoConfig,
  type CryptoAlgorithm,
  type SerializedKey,
  type SerializedHybridKeyPair,
  DEFAULT_CONFIG,
} from './types.js';

export interface KeyPair {
  algorithm: CryptoAlgorithm;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  keyId: string;
  createdAt: Date;
}

export interface HybridKeyPair {
  pqc: KeyPair;
  classical: KeyPair;
  keyId: string;
  createdAt: Date;
}

/**
 * Generate a unique key ID from public key material
 */
function generateKeyId(publicKey: Uint8Array): string {
  const hash = sha256(publicKey);
  // Take first 16 bytes, encode as hex with colons
  return Array.from(hash.slice(0, 16))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Base64url encode bytes
 */
function toBase64Url(bytes: Uint8Array): string {
  const base64 = Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Base64url decode to bytes
 */
function fromBase64Url(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

export class KeyManager {
  private config: CryptoConfig;

  constructor(config: Partial<CryptoConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Generate a post-quantum key pair (ML-DSA-65)
   */
  async generatePQCKeyPair(): Promise<KeyPair> {
    const seed = randomBytes(32);
    const { publicKey, secretKey } = ml_dsa65.keygen(seed);
    const keyId = generateKeyId(publicKey);

    return {
      algorithm: this.config.signatureAlgorithm as CryptoAlgorithm,
      publicKey,
      secretKey,
      keyId,
      createdAt: new Date(),
    };
  }

  /**
   * Generate a classical ECDSA P-256 key pair
   */
  async generateClassicalKeyPair(): Promise<KeyPair> {
    const secretKeyBytes = p256.utils.randomPrivateKey();
    const publicKeyBytes = p256.getPublicKey(secretKeyBytes);
    const keyId = generateKeyId(publicKeyBytes);

    return {
      algorithm: 'ecdsa-p256',
      publicKey: publicKeyBytes,
      secretKey: secretKeyBytes,
      keyId,
      createdAt: new Date(),
    };
  }

  /**
   * Generate a hybrid key pair (PQC + Classical)
   * This is the recommended mode for the transition period.
   */
  async generateHybridKeyPair(): Promise<HybridKeyPair> {
    const [pqc, classical] = await Promise.all([
      this.generatePQCKeyPair(),
      this.generateClassicalKeyPair(),
    ]);

    // Combined key ID from both public keys
    const combinedMaterial = new Uint8Array([
      ...pqc.publicKey.slice(0, 32),
      ...classical.publicKey,
    ]);
    const keyId = generateKeyId(combinedMaterial);

    return {
      pqc,
      classical,
      keyId,
      createdAt: new Date(),
    };
  }

  /**
   * Generate a key pair based on current config mode
   */
  async generateKeyPair(): Promise<HybridKeyPair | KeyPair> {
    switch (this.config.mode) {
      case 'hybrid':
        return this.generateHybridKeyPair();
      case 'pqc-only':
        return this.generatePQCKeyPair();
      case 'classical-only':
        return this.generateClassicalKeyPair();
    }
  }

  /**
   * Generate ML-KEM-768 key pair for key encapsulation
   */
  async generateKEMKeyPair(): Promise<KeyPair> {
    const seed = randomBytes(64);
    const { publicKey, secretKey } = ml_kem768.keygen(seed);
    const keyId = generateKeyId(publicKey);

    return {
      algorithm: 'ml-kem-768',
      publicKey,
      secretKey,
      keyId,
      createdAt: new Date(),
    };
  }

  /**
   * Serialize a key pair for storage
   */
  serializeKeyPair(keyPair: KeyPair, includeSecret = false): SerializedKey {
    return {
      algorithm: keyPair.algorithm,
      publicKey: toBase64Url(keyPair.publicKey),
      secretKey: includeSecret ? toBase64Url(keyPair.secretKey) : undefined,
      keyId: keyPair.keyId,
      createdAt: keyPair.createdAt.toISOString(),
    };
  }

  /**
   * Serialize a hybrid key pair for storage
   */
  serializeHybridKeyPair(
    hybrid: HybridKeyPair,
    includeSecret = false
  ): SerializedHybridKeyPair {
    return {
      pqc: this.serializeKeyPair(hybrid.pqc, includeSecret),
      classical: this.serializeKeyPair(hybrid.classical, includeSecret),
      mode: this.config.mode,
      keyId: hybrid.keyId,
    };
  }

  /**
   * Deserialize a key pair from storage
   */
  deserializeKeyPair(serialized: SerializedKey): KeyPair {
    return {
      algorithm: serialized.algorithm,
      publicKey: fromBase64Url(serialized.publicKey),
      secretKey: serialized.secretKey
        ? fromBase64Url(serialized.secretKey)
        : new Uint8Array(0),
      keyId: serialized.keyId,
      createdAt: new Date(serialized.createdAt),
    };
  }

  /**
   * Deserialize a hybrid key pair from storage
   */
  deserializeHybridKeyPair(serialized: SerializedHybridKeyPair): HybridKeyPair {
    return {
      pqc: this.deserializeKeyPair(serialized.pqc),
      classical: this.deserializeKeyPair(serialized.classical),
      keyId: serialized.keyId,
      createdAt: new Date(serialized.pqc.createdAt),
    };
  }
}

export { toBase64Url, fromBase64Url, generateKeyId };
