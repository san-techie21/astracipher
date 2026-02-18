/**
 * Key Encapsulation Mechanism (KEM) for AgentPass
 *
 * Uses ML-KEM-768 (FIPS 203) for quantum-resistant key exchange.
 * Used to establish shared secrets between agents for encrypted communication.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { toBase64Url, fromBase64Url, type KeyPair } from './key-manager.js';

export interface EncapsulationResult {
  /** The shared secret (32 bytes) */
  sharedSecret: Uint8Array;
  /** The ciphertext to send to the recipient */
  ciphertext: string; // base64url
  /** Algorithm used */
  algorithm: string;
}

export interface DecapsulationResult {
  /** The shared secret (32 bytes) */
  sharedSecret: Uint8Array;
  /** Whether decapsulation was successful */
  success: boolean;
  error?: string;
}

export class KEM {
  /**
   * Encapsulate: generate a shared secret and ciphertext using recipient's public key
   * The ciphertext is sent to the recipient who can decapsulate it with their secret key.
   */
  static encapsulate(recipientPublicKey: Uint8Array): EncapsulationResult {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(recipientPublicKey);

    return {
      sharedSecret,
      ciphertext: toBase64Url(cipherText),
      algorithm: 'ml-kem-768',
    };
  }

  /**
   * Decapsulate: recover the shared secret using own secret key and received ciphertext
   */
  static decapsulate(
    ciphertext: string,
    secretKey: Uint8Array
  ): DecapsulationResult {
    try {
      const cipherBytes = fromBase64Url(ciphertext);
      const sharedSecret = ml_kem768.decapsulate(cipherBytes, secretKey);

      return {
        sharedSecret,
        success: true,
      };
    } catch (error) {
      // PUB-LOW-3 FIX: Don't leak underlying library error details
      return {
        sharedSecret: new Uint8Array(0),
        success: false,
        error: 'Decapsulation failed: invalid ciphertext or key mismatch',
      };
    }
  }

  /**
   * Derive a purpose-specific key from a shared secret.
   *
   * MED-9 FIX: Uses HKDF (RFC 5869) with SHA-256 instead of raw SHA-256.
   * HKDF provides proper extract-then-expand key derivation with domain separation.
   *
   * - salt: domain separator (provides key independence per purpose)
   * - info: AgentPass protocol version (prevents cross-version collisions)
   * - ikm: the raw shared secret from ML-KEM-768
   */
  static deriveKey(sharedSecret: Uint8Array, purpose: string): Uint8Array {
    const encoder = new TextEncoder();
    const salt = encoder.encode(`agentpass:kem:${purpose}`);
    const info = encoder.encode('agentpass-v0.1');
    return hkdf(sha256, sharedSecret, salt, info, 32); // 256-bit derived key
  }

  /**
   * Establish a shared secret between two agents
   * Returns both the shared secret and the ciphertext to send.
   */
  static async establishChannel(
    recipientPublicKey: Uint8Array,
    purpose: string = 'agent-communication'
  ): Promise<{
    sharedSecret: Uint8Array;
    derivedKey: Uint8Array;
    ciphertext: string;
  }> {
    const { sharedSecret, ciphertext } = KEM.encapsulate(recipientPublicKey);
    const derivedKey = KEM.deriveKey(sharedSecret, purpose);

    return { sharedSecret, derivedKey, ciphertext };
  }
}
