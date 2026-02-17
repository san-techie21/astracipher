/**
 * Key Encapsulation Mechanism (KEM) for AgentPass
 *
 * Uses ML-KEM-768 (FIPS 203) for quantum-resistant key exchange.
 * Used to establish shared secrets between agents for encrypted communication.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { sha256 } from '@noble/hashes/sha256';
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
      return {
        sharedSecret: new Uint8Array(0),
        success: false,
        error: `Decapsulation failed: ${error instanceof Error ? error.message : 'unknown'}`,
      };
    }
  }

  /**
   * Derive a purpose-specific key from a shared secret
   * Uses SHA-256 with a domain separator for key derivation.
   */
  static deriveKey(sharedSecret: Uint8Array, purpose: string): Uint8Array {
    const encoder = new TextEncoder();
    const domainSeparator = encoder.encode(`agentpass:kem:${purpose}`);
    const input = new Uint8Array([...domainSeparator, ...sharedSecret]);
    return sha256(input);
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
