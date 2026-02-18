/**
 * Comprehensive tests for @agentpass/crypto
 *
 * Tests post-quantum cryptographic primitives:
 * - ML-DSA-65 (FIPS 204) key generation and signing
 * - ECDSA P-256 key generation and signing
 * - Hybrid (PQC + Classical) key generation, signing, and verification
 * - ML-KEM-768 (FIPS 203) key encapsulation and decapsulation
 * - Key serialization/deserialization
 * - JSON signing and verification
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { AgentPassCrypto } from './crypto.js';
import { KeyManager, type HybridKeyPair, type KeyPair } from './key-manager.js';
import { Signer } from './signer.js';
import { KEM } from './kem.js';
import { DEFAULT_CONFIG } from './types.js';

// ============================
// Key Generation Tests
// ============================

describe('KeyManager', () => {
  let keyManager: KeyManager;

  beforeEach(() => {
    keyManager = new KeyManager();
  });

  describe('PQC Key Generation (ML-DSA-65)', () => {
    it('should generate a valid PQC key pair', async () => {
      const kp = await keyManager.generatePQCKeyPair();

      expect(kp.algorithm).toBe('ml-dsa-65');
      expect(kp.publicKey).toBeInstanceOf(Uint8Array);
      expect(kp.secretKey).toBeInstanceOf(Uint8Array);
      expect(kp.publicKey.length).toBeGreaterThan(0);
      expect(kp.secretKey.length).toBeGreaterThan(0);
      expect(kp.keyId).toBeTruthy();
      expect(typeof kp.keyId).toBe('string');
      expect(kp.keyId.length).toBe(32); // 16 bytes hex encoded
      expect(kp.createdAt).toBeInstanceOf(Date);
    });

    it('should generate unique key pairs each time', async () => {
      const kp1 = await keyManager.generatePQCKeyPair();
      const kp2 = await keyManager.generatePQCKeyPair();

      expect(kp1.keyId).not.toBe(kp2.keyId);
      expect(kp1.publicKey).not.toEqual(kp2.publicKey);
    });
  });

  describe('Classical Key Generation (ECDSA P-256)', () => {
    it('should generate a valid classical key pair', async () => {
      const kp = await keyManager.generateClassicalKeyPair();

      expect(kp.algorithm).toBe('ecdsa-p256');
      expect(kp.publicKey).toBeInstanceOf(Uint8Array);
      expect(kp.secretKey).toBeInstanceOf(Uint8Array);
      expect(kp.publicKey.length).toBe(33); // compressed P-256 public key
      expect(kp.keyId).toBeTruthy();
    });
  });

  describe('Hybrid Key Generation (ML-DSA-65 + ECDSA P-256)', () => {
    it('should generate a valid hybrid key pair', async () => {
      const hybrid = await keyManager.generateHybridKeyPair();

      expect(hybrid.pqc).toBeDefined();
      expect(hybrid.classical).toBeDefined();
      expect(hybrid.pqc.algorithm).toBe('ml-dsa-65');
      expect(hybrid.classical.algorithm).toBe('ecdsa-p256');
      expect(hybrid.keyId).toBeTruthy();
      expect(hybrid.createdAt).toBeInstanceOf(Date);
    });

    it('should have separate PQC and classical key material', async () => {
      const hybrid = await keyManager.generateHybridKeyPair();

      expect(hybrid.pqc.publicKey).not.toEqual(hybrid.classical.publicKey);
      expect(hybrid.pqc.secretKey).not.toEqual(hybrid.classical.secretKey);
      expect(hybrid.pqc.keyId).not.toBe(hybrid.classical.keyId);
    });
  });

  describe('generateKeyPair (config-based)', () => {
    it('should generate hybrid keys by default', async () => {
      const result = await keyManager.generateKeyPair();
      expect('pqc' in result).toBe(true);
      expect('classical' in result).toBe(true);
    });

    it('should generate PQC-only keys when configured', async () => {
      const pqcManager = new KeyManager({ ...DEFAULT_CONFIG, mode: 'pqc-only' });
      const result = await pqcManager.generateKeyPair();
      expect('pqc' in result).toBe(false);
      expect((result as KeyPair).algorithm).toBe('ml-dsa-65');
    });

    it('should generate classical-only keys when configured', async () => {
      const classicalManager = new KeyManager({ ...DEFAULT_CONFIG, mode: 'classical-only' });
      const result = await classicalManager.generateKeyPair();
      expect('pqc' in result).toBe(false);
      expect((result as KeyPair).algorithm).toBe('ecdsa-p256');
    });
  });

  describe('KEM Key Generation (ML-KEM-768)', () => {
    it('should generate a valid KEM key pair', async () => {
      const kp = await keyManager.generateKEMKeyPair();

      expect(kp.algorithm).toBe('ml-kem-768');
      expect(kp.publicKey).toBeInstanceOf(Uint8Array);
      expect(kp.secretKey).toBeInstanceOf(Uint8Array);
      expect(kp.publicKey.length).toBeGreaterThan(0);
      expect(kp.keyId).toBeTruthy();
    });
  });

  describe('Key Serialization / Deserialization', () => {
    it('should round-trip a PQC key pair (public only)', async () => {
      const original = await keyManager.generatePQCKeyPair();
      const serialized = keyManager.serializeKeyPair(original, false);

      expect(serialized.publicKey).toBeTruthy();
      expect(serialized.secretKey).toBeUndefined();
      expect(serialized.algorithm).toBe('ml-dsa-65');
      expect(serialized.keyId).toBe(original.keyId);
    });

    it('should round-trip a PQC key pair (with secret)', async () => {
      const original = await keyManager.generatePQCKeyPair();
      const serialized = keyManager.serializeKeyPair(original, true);
      const deserialized = keyManager.deserializeKeyPair(serialized);

      expect(deserialized.algorithm).toBe(original.algorithm);
      expect(deserialized.keyId).toBe(original.keyId);
      expect(deserialized.publicKey).toEqual(original.publicKey);
      expect(deserialized.secretKey).toEqual(original.secretKey);
    });

    it('should round-trip a hybrid key pair', async () => {
      const original = await keyManager.generateHybridKeyPair();
      const serialized = keyManager.serializeHybridKeyPair(original, true);
      const deserialized = keyManager.deserializeHybridKeyPair(serialized);

      expect(deserialized.keyId).toBe(original.keyId);
      expect(deserialized.pqc.publicKey).toEqual(original.pqc.publicKey);
      expect(deserialized.pqc.secretKey).toEqual(original.pqc.secretKey);
      expect(deserialized.classical.publicKey).toEqual(original.classical.publicKey);
      expect(deserialized.classical.secretKey).toEqual(original.classical.secretKey);
    });
  });
});

// ============================
// Signature Tests
// ============================

describe('Signer', () => {
  let keyManager: KeyManager;

  beforeEach(() => {
    keyManager = new KeyManager();
  });

  describe('PQC Signing (ML-DSA-65)', () => {
    it('should sign and verify with PQC keys', async () => {
      const kp = await keyManager.generatePQCKeyPair();
      const message = new TextEncoder().encode('Hello AgentPass');

      const signature = Signer.signPQC(message, kp.secretKey);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBeGreaterThan(0);

      const valid = Signer.verifyPQC(message, signature, kp.publicKey);
      expect(valid).toBe(true);
    });

    it('should reject tampered messages', async () => {
      const kp = await keyManager.generatePQCKeyPair();
      const message = new TextEncoder().encode('Original message');
      const signature = Signer.signPQC(message, kp.secretKey);

      const tampered = new TextEncoder().encode('Tampered message');
      const valid = Signer.verifyPQC(tampered, signature, kp.publicKey);
      expect(valid).toBe(false);
    });

    it('should reject wrong public key', async () => {
      const kp1 = await keyManager.generatePQCKeyPair();
      const kp2 = await keyManager.generatePQCKeyPair();
      const message = new TextEncoder().encode('Test message');

      const signature = Signer.signPQC(message, kp1.secretKey);
      const valid = Signer.verifyPQC(message, signature, kp2.publicKey);
      expect(valid).toBe(false);
    });
  });

  describe('Classical Signing (ECDSA P-256)', () => {
    it('should sign and verify with classical keys', async () => {
      const kp = await keyManager.generateClassicalKeyPair();
      const message = new TextEncoder().encode('Hello Classical');

      const signature = Signer.signClassical(message, kp.secretKey);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64); // compact ECDSA signature

      const valid = Signer.verifyClassical(message, signature, kp.publicKey);
      expect(valid).toBe(true);
    });

    it('should reject tampered messages', async () => {
      const kp = await keyManager.generateClassicalKeyPair();
      const message = new TextEncoder().encode('Original');
      const signature = Signer.signClassical(message, kp.secretKey);

      const tampered = new TextEncoder().encode('Tampered');
      const valid = Signer.verifyClassical(tampered, signature, kp.publicKey);
      expect(valid).toBe(false);
    });
  });

  describe('Hybrid Signing (ML-DSA-65 + ECDSA P-256)', () => {
    it('should create and verify a hybrid signature', async () => {
      const hybrid = await keyManager.generateHybridKeyPair();
      const message = new TextEncoder().encode('Hybrid security');

      const sigResult = await Signer.signHybrid(message, hybrid);

      expect(sigResult.mode).toBe('hybrid');
      expect(sigResult.pqcSignature).toBeTruthy();
      expect(sigResult.classicalSignature).toBeTruthy();
      expect(sigResult.algorithms.pqc).toBe('ml-dsa-65');
      expect(sigResult.algorithms.classical).toBe('ecdsa-p256');
      expect(sigResult.keyId).toBe(hybrid.keyId);
      expect(sigResult.messageHash).toBeTruthy();

      const verifyResult = await Signer.verifyHybrid(message, sigResult, {
        pqcPublicKey: hybrid.pqc.publicKey,
        classicalPublicKey: hybrid.classical.publicKey,
      });

      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.pqcValid).toBe(true);
      expect(verifyResult.classicalValid).toBe(true);
    });

    it('should reject if PQC signature fails', async () => {
      const hybrid = await keyManager.generateHybridKeyPair();
      const wrongHybrid = await keyManager.generateHybridKeyPair();
      const message = new TextEncoder().encode('Test');

      const sigResult = await Signer.signHybrid(message, hybrid);

      const verifyResult = await Signer.verifyHybrid(message, sigResult, {
        pqcPublicKey: wrongHybrid.pqc.publicKey, // wrong PQC key
        classicalPublicKey: hybrid.classical.publicKey,
      });

      expect(verifyResult.valid).toBe(false);
      expect(verifyResult.pqcValid).toBe(false);
      expect(verifyResult.classicalValid).toBe(true);
    });

    it('should reject if classical signature fails', async () => {
      const hybrid = await keyManager.generateHybridKeyPair();
      const wrongHybrid = await keyManager.generateHybridKeyPair();
      const message = new TextEncoder().encode('Test');

      const sigResult = await Signer.signHybrid(message, hybrid);

      const verifyResult = await Signer.verifyHybrid(message, sigResult, {
        pqcPublicKey: hybrid.pqc.publicKey,
        classicalPublicKey: wrongHybrid.classical.publicKey, // wrong classical key
      });

      expect(verifyResult.valid).toBe(false);
      expect(verifyResult.pqcValid).toBe(true);
      expect(verifyResult.classicalValid).toBe(false);
    });
  });

  describe('Generic verify()', () => {
    it('should route hybrid signature to verifyHybrid', async () => {
      const hybrid = await keyManager.generateHybridKeyPair();
      const message = new TextEncoder().encode('Generic verify test');
      const sig = await Signer.signHybrid(message, hybrid);

      const result = await Signer.verify(message, sig, {
        pqcPublicKey: hybrid.pqc.publicKey,
        classicalPublicKey: hybrid.classical.publicKey,
      });

      expect(result.valid).toBe(true);
    });

    it('should verify PQC-only signatures', async () => {
      const kp = await keyManager.generatePQCKeyPair();
      const message = new TextEncoder().encode('PQC only');
      const sig = await Signer.signPQCOnly(message, kp);

      const result = await Signer.verify(message, sig, {
        pqcPublicKey: kp.publicKey,
      });

      expect(result.valid).toBe(true);
      expect(result.pqcValid).toBe(true);
    });
  });
});

// ============================
// KEM Tests (ML-KEM-768)
// ============================

describe('KEM (ML-KEM-768)', () => {
  let keyManager: KeyManager;

  beforeEach(() => {
    keyManager = new KeyManager();
  });

  it('should encapsulate and decapsulate a shared secret', async () => {
    const kemKeys = await keyManager.generateKEMKeyPair();

    const encapResult = KEM.encapsulate(kemKeys.publicKey);
    expect(encapResult.sharedSecret).toBeInstanceOf(Uint8Array);
    expect(encapResult.sharedSecret.length).toBe(32);
    expect(encapResult.ciphertext).toBeTruthy();
    expect(encapResult.algorithm).toBe('ml-kem-768');

    const decapResult = KEM.decapsulate(encapResult.ciphertext, kemKeys.secretKey);
    expect(decapResult.success).toBe(true);
    expect(decapResult.sharedSecret).toEqual(encapResult.sharedSecret);
  });

  it('should fail decapsulation with wrong secret key', async () => {
    const kemKeys1 = await keyManager.generateKEMKeyPair();
    const kemKeys2 = await keyManager.generateKEMKeyPair();

    const encapResult = KEM.encapsulate(kemKeys1.publicKey);
    const decapResult = KEM.decapsulate(encapResult.ciphertext, kemKeys2.secretKey);

    // ML-KEM decapsulation with wrong key returns a different shared secret (implicit rejection)
    // The shared secrets should not match
    expect(decapResult.sharedSecret).not.toEqual(encapResult.sharedSecret);
  });

  it('should derive purpose-specific keys', () => {
    const sharedSecret = new Uint8Array(32).fill(42);
    const key1 = KEM.deriveKey(sharedSecret, 'encryption');
    const key2 = KEM.deriveKey(sharedSecret, 'authentication');

    expect(key1).toBeInstanceOf(Uint8Array);
    expect(key1.length).toBe(32);
    // Different purposes produce different derived keys
    expect(key1).not.toEqual(key2);
  });

  it('should establish a full communication channel', async () => {
    const kemKeys = await keyManager.generateKEMKeyPair();

    const channel = await KEM.establishChannel(kemKeys.publicKey, 'agent-communication');
    expect(channel.sharedSecret.length).toBe(32);
    expect(channel.derivedKey.length).toBe(32);
    expect(channel.ciphertext).toBeTruthy();

    // Recipient can recover the same shared secret
    const recovered = KEM.decapsulate(channel.ciphertext, kemKeys.secretKey);
    expect(recovered.success).toBe(true);
    expect(recovered.sharedSecret).toEqual(channel.sharedSecret);
  });
});

// ============================
// AgentPassCrypto (High-Level API) Tests
// ============================

describe('AgentPassCrypto', () => {
  let crypto: AgentPassCrypto;

  beforeEach(() => {
    crypto = new AgentPassCrypto();
  });

  it('should use hybrid mode by default', () => {
    const config = crypto.getConfig();
    expect(config.mode).toBe('hybrid');
    expect(config.signatureAlgorithm).toBe('ml-dsa-65');
    expect(config.classicalSignatureAlgorithm).toBe('ecdsa-p256');
  });

  it('should generate identity keys (hybrid by default)', async () => {
    const keys = await crypto.generateIdentityKeys();
    expect('pqc' in keys).toBe(true);
    expect('classical' in keys).toBe(true);
  });

  it('should generate KEM keys', async () => {
    const keys = await crypto.generateKEMKeys();
    expect(keys.algorithm).toBe('ml-kem-768');
  });

  describe('sign / verify (string)', () => {
    it('should sign and verify a string with hybrid keys', async () => {
      const keys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
      const sig = await crypto.sign('Hello AgentPass', keys);

      expect(sig.mode).toBe('hybrid');

      const result = await crypto.verify('Hello AgentPass', sig, {
        pqcPublicKey: keys.pqc.publicKey,
        classicalPublicKey: keys.classical.publicKey,
      });

      expect(result.valid).toBe(true);
    });

    it('should reject tampered data', async () => {
      const keys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
      const sig = await crypto.sign('Original', keys);

      const result = await crypto.verify('Modified', sig, {
        pqcPublicKey: keys.pqc.publicKey,
        classicalPublicKey: keys.classical.publicKey,
      });

      expect(result.valid).toBe(false);
    });
  });

  describe('signJSON / verifyJSON', () => {
    it('should sign and verify a JSON object', async () => {
      const keys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
      const obj = {
        id: 'did:agentpass:testnet:abc123',
        name: 'TestAgent',
        capabilities: ['read', 'write'],
      };

      const sig = await crypto.signJSON(obj, keys);
      const result = await crypto.verifyJSON(obj, sig, {
        pqcPublicKey: keys.pqc.publicKey,
        classicalPublicKey: keys.classical.publicKey,
      });

      expect(result.valid).toBe(true);
    });

    it('should use canonical JSON serialization', async () => {
      const keys = (await crypto.generateIdentityKeys()) as HybridKeyPair;

      // Same keys, different insertion order
      const obj1 = { b: 2, a: 1 };
      const obj2 = { a: 1, b: 2 };

      const sig = await crypto.signJSON(obj1, keys);
      const result = await crypto.verifyJSON(obj2, sig, {
        pqcPublicKey: keys.pqc.publicKey,
        classicalPublicKey: keys.classical.publicKey,
      });

      // Both should produce the same canonical JSON
      expect(result.valid).toBe(true);
    });
  });

  describe('encapsulate / decapsulate', () => {
    it('should perform key encapsulation and decapsulation', async () => {
      const kemKeys = await crypto.generateKEMKeys();

      const encap = await crypto.encapsulate(kemKeys.publicKey);
      const decap = await crypto.decapsulate(encap.ciphertext, kemKeys.secretKey);

      expect(decap.success).toBe(true);
      expect(decap.sharedSecret).toEqual(encap.sharedSecret);
    });
  });
});
