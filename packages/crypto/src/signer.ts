/**
 * Digital signature operations for AgentPass
 *
 * Supports hybrid signatures: ML-DSA-65 (PQC) + ECDSA P-256 (classical)
 * Both signatures must verify for a hybrid signature to be valid.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { type KeyPair, type HybridKeyPair, toBase64Url, fromBase64Url } from './key-manager.js';
import { type CryptoMode, type CryptoAlgorithm } from './types.js';

export interface SignatureResult {
  /** The signature mode used */
  mode: CryptoMode;
  /** PQC signature (ML-DSA-65) */
  pqcSignature?: string; // base64url
  /** Classical signature (ECDSA P-256) */
  classicalSignature?: string; // base64url
  /** Algorithm identifiers */
  algorithms: {
    pqc?: CryptoAlgorithm;
    classical?: CryptoAlgorithm;
  };
  /** Key ID of the signing key */
  keyId: string;
  /** Timestamp of signing */
  signedAt: string;
  /** SHA-256 hash of the signed message */
  messageHash: string;
}

export interface VerifyResult {
  /** Whether the signature is valid */
  valid: boolean;
  /** PQC signature verification result */
  pqcValid?: boolean;
  /** Classical signature verification result */
  classicalValid?: boolean;
  /** Key ID that was verified against */
  keyId: string;
  /** Any error that occurred */
  error?: string;
}

export class Signer {
  /**
   * Sign a message with ML-DSA-65 (post-quantum)
   */
  static signPQC(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    return ml_dsa65.sign(secretKey, message);
  }

  /**
   * Sign a message with ECDSA P-256 (classical)
   */
  static signClassical(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    const msgHash = sha256(message);
    const sig = p256.sign(msgHash, secretKey);
    return sig.toCompactRawBytes();
  }

  /**
   * Create a hybrid signature (PQC + Classical)
   */
  static async signHybrid(
    message: Uint8Array,
    hybridKey: HybridKeyPair
  ): Promise<SignatureResult> {
    const pqcSig = Signer.signPQC(message, hybridKey.pqc.secretKey);
    const classicalSig = Signer.signClassical(
      message,
      hybridKey.classical.secretKey
    );
    const msgHash = sha256(message);

    return {
      mode: 'hybrid',
      pqcSignature: toBase64Url(pqcSig),
      classicalSignature: toBase64Url(classicalSig),
      algorithms: {
        pqc: hybridKey.pqc.algorithm,
        classical: hybridKey.classical.algorithm,
      },
      keyId: hybridKey.keyId,
      signedAt: new Date().toISOString(),
      messageHash: toBase64Url(msgHash),
    };
  }

  /**
   * Create a PQC-only signature
   */
  static async signPQCOnly(
    message: Uint8Array,
    keyPair: KeyPair
  ): Promise<SignatureResult> {
    const pqcSig = Signer.signPQC(message, keyPair.secretKey);
    const msgHash = sha256(message);

    return {
      mode: 'pqc-only',
      pqcSignature: toBase64Url(pqcSig),
      algorithms: { pqc: keyPair.algorithm },
      keyId: keyPair.keyId,
      signedAt: new Date().toISOString(),
      messageHash: toBase64Url(msgHash),
    };
  }

  /**
   * Verify a PQC signature (ML-DSA-65)
   */
  static verifyPQC(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array
  ): boolean {
    try {
      return ml_dsa65.verify(publicKey, message, signature);
    } catch {
      return false;
    }
  }

  /**
   * Verify a classical signature (ECDSA P-256)
   */
  static verifyClassical(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array
  ): boolean {
    try {
      const msgHash = sha256(message);
      return p256.verify(signature, msgHash, publicKey);
    } catch {
      return false;
    }
  }

  /**
   * Verify a hybrid signature — BOTH must be valid
   */
  static async verifyHybrid(
    message: Uint8Array,
    signatureResult: SignatureResult,
    hybridPublicKeys: { pqcPublicKey: Uint8Array; classicalPublicKey: Uint8Array }
  ): Promise<VerifyResult> {
    if (signatureResult.mode !== 'hybrid') {
      return {
        valid: false,
        keyId: signatureResult.keyId,
        error: `Expected hybrid signature, got ${signatureResult.mode}`,
      };
    }

    if (!signatureResult.pqcSignature || !signatureResult.classicalSignature) {
      return {
        valid: false,
        keyId: signatureResult.keyId,
        error: 'Missing PQC or classical signature in hybrid mode',
      };
    }

    const pqcSig = fromBase64Url(signatureResult.pqcSignature);
    const classicalSig = fromBase64Url(signatureResult.classicalSignature);

    const pqcValid = Signer.verifyPQC(
      message,
      pqcSig,
      hybridPublicKeys.pqcPublicKey
    );
    const classicalValid = Signer.verifyClassical(
      message,
      classicalSig,
      hybridPublicKeys.classicalPublicKey
    );

    return {
      valid: pqcValid && classicalValid, // BOTH must pass
      pqcValid,
      classicalValid,
      keyId: signatureResult.keyId,
      error:
        !pqcValid && !classicalValid
          ? 'Both PQC and classical signatures failed'
          : !pqcValid
            ? 'PQC signature verification failed'
            : !classicalValid
              ? 'Classical signature verification failed'
              : undefined,
    };
  }

  /**
   * MED-8 FIX: Maximum signature age (24 hours).
   * Signatures older than this are considered stale and rejected.
   */
  static readonly MAX_SIGNATURE_AGE_MS = 24 * 60 * 60 * 1000;

  /**
   * Verify any signature based on its mode.
   *
   * MED-8 FIX: Now validates the signedAt timestamp to reject stale signatures.
   */
  static async verify(
    message: Uint8Array,
    signatureResult: SignatureResult,
    publicKeys: {
      pqcPublicKey?: Uint8Array;
      classicalPublicKey?: Uint8Array;
    },
    options?: { maxAge?: number; skipTimestampCheck?: boolean }
  ): Promise<VerifyResult> {
    // MED-8 FIX: Verify signedAt timestamp
    if (!options?.skipTimestampCheck && signatureResult.signedAt) {
      const signedAt = new Date(signatureResult.signedAt).getTime();
      const now = Date.now();
      const maxAge = options?.maxAge ?? Signer.MAX_SIGNATURE_AGE_MS;
      const fiveMinuteFuture = 5 * 60 * 1000; // 5-min clock skew allowance

      if (isNaN(signedAt)) {
        return {
          valid: false,
          keyId: signatureResult.keyId,
          error: 'Invalid signedAt timestamp',
        };
      }

      if (signedAt > now + fiveMinuteFuture) {
        return {
          valid: false,
          keyId: signatureResult.keyId,
          error: 'Signature is from the future',
        };
      }

      if (now - signedAt > maxAge) {
        return {
          valid: false,
          keyId: signatureResult.keyId,
          error: `Signature is stale (signed ${Math.floor((now - signedAt) / 1000)}s ago, max ${Math.floor(maxAge / 1000)}s)`,
        };
      }
    }

    switch (signatureResult.mode) {
      case 'hybrid': {
        if (!publicKeys.pqcPublicKey || !publicKeys.classicalPublicKey) {
          return {
            valid: false,
            keyId: signatureResult.keyId,
            error: 'Hybrid verification requires both PQC and classical public keys',
          };
        }
        return Signer.verifyHybrid(message, signatureResult, {
          pqcPublicKey: publicKeys.pqcPublicKey,
          classicalPublicKey: publicKeys.classicalPublicKey,
        });
      }
      case 'pqc-only': {
        if (!publicKeys.pqcPublicKey || !signatureResult.pqcSignature) {
          return {
            valid: false,
            keyId: signatureResult.keyId,
            error: 'PQC verification requires PQC public key and signature',
          };
        }
        const pqcSig = fromBase64Url(signatureResult.pqcSignature);
        const pqcValid = Signer.verifyPQC(message, pqcSig, publicKeys.pqcPublicKey);
        return { valid: pqcValid, pqcValid, keyId: signatureResult.keyId };
      }
      case 'classical-only': {
        if (!publicKeys.classicalPublicKey || !signatureResult.classicalSignature) {
          return {
            valid: false,
            keyId: signatureResult.keyId,
            error: 'Classical verification requires classical public key and signature',
          };
        }
        const classicalSig = fromBase64Url(signatureResult.classicalSignature);
        const classicalValid = Signer.verifyClassical(
          message,
          classicalSig,
          publicKeys.classicalPublicKey
        );
        return {
          valid: classicalValid,
          classicalValid,
          keyId: signatureResult.keyId,
        };
      }
    }
  }
}
