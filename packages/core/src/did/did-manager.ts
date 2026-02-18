/**
 * DID (Decentralized Identifier) Manager
 *
 * Implements W3C DID v1.1 with the did:astracipher method.
 * Each AI agent gets a unique DID that serves as its identity anchor.
 *
 * DID format: did:astracipher:<network>:<unique-id>
 * Example:    did:astracipher:mainnet:a1b2c3d4e5f6
 */

import { v4 as uuidv4 } from 'uuid';
import {
  AstraCipherCrypto,
  type HybridKeyPair,
  type KeyPair,
  type SignatureResult,
} from '@astracipher/crypto';

export interface DIDVerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: Record<string, unknown>;
}

export interface DIDService {
  id: string;
  type: string;
  serviceEndpoint: string;
  description?: string;
}

export interface DIDDocument {
  '@context': string[];
  id: string;
  controller: string | string[];
  verificationMethod: DIDVerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  keyAgreement?: string[];
  service?: DIDService[];
  created: string;
  updated: string;
  deactivated?: boolean;
  proof?: SignatureResult;
}

export interface CreateDIDOptions {
  /** Network: mainnet, testnet, or local */
  network?: string;
  /** Controller DID (who controls this agent's identity) */
  controller?: string;
  /** Services the agent provides */
  services?: DIDService[];
  /** Agent metadata */
  metadata?: Record<string, unknown>;
}

export interface DIDManagerOptions {
  crypto?: AstraCipherCrypto;
  /** Registry URL for remote DID resolution (e.g. http://localhost:3456) */
  registryUrl?: string;
}

/**
 * MED-1 FIX: Decode a multibase-encoded string.
 * Supports 'u' (base64url) and 'z' (legacy base64 compat).
 */
function decodeMultibase(encoded: string): Uint8Array {
  if (!encoded || encoded.length < 2) {
    throw new Error('Invalid multibase string: too short');
  }
  const prefix = encoded[0];
  const data = encoded.slice(1);
  switch (prefix) {
    case 'u': // base64url (correct per multibase spec)
      return new Uint8Array(Buffer.from(data, 'base64url'));
    case 'z': // base58btc — but for backward compat, try base64 first
      // Our old code incorrectly used z+base64; support both for migration
      return new Uint8Array(Buffer.from(data, 'base64'));
    default:
      throw new Error(`Unsupported multibase prefix: '${prefix}'`);
  }
}

export class DIDManager {
  private crypto: AstraCipherCrypto;
  private registryUrl?: string;

  constructor(cryptoOrOptions?: AstraCipherCrypto | DIDManagerOptions) {
    if (cryptoOrOptions instanceof AstraCipherCrypto) {
      this.crypto = cryptoOrOptions;
    } else if (cryptoOrOptions && 'crypto' in cryptoOrOptions) {
      this.crypto = cryptoOrOptions.crypto || new AstraCipherCrypto();
      this.registryUrl = cryptoOrOptions.registryUrl;
    } else {
      this.crypto = new AstraCipherCrypto();
    }
  }

  /**
   * Set the registry URL for remote DID resolution
   */
  setRegistryUrl(url: string): void {
    this.registryUrl = url;
  }

  /**
   * Generate a new DID for an AI agent
   */
  async createDID(
    options: CreateDIDOptions = {}
  ): Promise<{ did: DIDDocument; keys: HybridKeyPair | KeyPair }> {
    const network = options.network || 'mainnet';
    const keys = await this.crypto.generateIdentityKeys();
    const keyId = 'pqc' in keys ? keys.keyId : keys.keyId;
    const uniqueId = keyId.slice(0, 24);
    const didId = `did:astracipher:${network}:${uniqueId}`;

    const now = new Date().toISOString();

    // Build verification methods
    const verificationMethods: DIDVerificationMethod[] = [];
    const authenticationIds: string[] = [];
    const assertionMethodIds: string[] = [];
    const keyAgreementIds: string[] = [];

    if ('pqc' in keys) {
      // Hybrid key pair
      const hybrid = keys as HybridKeyPair;

      // PQC verification method
      const pqcMethodId = `${didId}#key-pqc-1`;
      verificationMethods.push({
        id: pqcMethodId,
        type: 'ML-DSA-65-2024',
        controller: didId,
        publicKeyMultibase: `u${Buffer.from(hybrid.pqc.publicKey).toString('base64url')}`,
      });
      authenticationIds.push(pqcMethodId);
      assertionMethodIds.push(pqcMethodId);

      // Classical verification method
      const classicalMethodId = `${didId}#key-classical-1`;
      verificationMethods.push({
        id: classicalMethodId,
        type: 'EcdsaSecp256r1VerificationKey2019',
        controller: didId,
        publicKeyMultibase: `u${Buffer.from(hybrid.classical.publicKey).toString('base64url')}`,
      });
      authenticationIds.push(classicalMethodId);
      assertionMethodIds.push(classicalMethodId);
    } else {
      // Single key pair
      const single = keys as KeyPair;
      const methodId = `${didId}#key-1`;
      verificationMethods.push({
        id: methodId,
        type:
          single.algorithm === 'ml-dsa-65'
            ? 'ML-DSA-65-2024'
            : 'EcdsaSecp256r1VerificationKey2019',
        controller: didId,
        publicKeyMultibase: `u${Buffer.from(single.publicKey).toString('base64url')}`,
      });
      authenticationIds.push(methodId);
      assertionMethodIds.push(methodId);
    }

    // Build DID document
    const didDocument: DIDDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1',
        'https://astracipher.com/ns/v1',
      ],
      id: didId,
      controller: options.controller || didId,
      verificationMethod: verificationMethods,
      authentication: authenticationIds,
      assertionMethod: assertionMethodIds,
      ...(keyAgreementIds.length > 0 ? { keyAgreement: keyAgreementIds } : {}),
      ...(options.services ? { service: options.services } : {}),
      created: now,
      updated: now,
    };

    // Self-sign the DID document
    const proof = await this.crypto.signJSON(
      didDocument as unknown as Record<string, unknown>,
      keys
    );
    didDocument.proof = proof;

    return { did: didDocument, keys };
  }

  /**
   * Resolve a DID to its document from the AstraCipher registry.
   *
   * Resolution order:
   *   1. Remote registry (if registryUrl is configured)
   *   2. Returns null if no registry or DID not found
   *
   * @param did - The DID to resolve (e.g. did:astracipher:testnet:abc123)
   * @param options - Optional overrides for this resolution call
   */
  async resolveDID(
    did: string,
    options?: { registryUrl?: string }
  ): Promise<DIDDocument | null> {
    // Validate DID format
    if (!did.startsWith('did:astracipher:')) {
      throw new Error(
        `Invalid DID method: expected did:astracipher:*, got ${did}`
      );
    }

    const url = options?.registryUrl || this.registryUrl;

    if (!url) {
      console.warn(
        `DID resolution for ${did} requires a registry URL. ` +
          'Pass registryUrl in config or use AstraCipher({ registryUrl: "..." }).'
      );
      return null;
    }

    // Query the AstraCipher registry server
    try {
      const endpoint = `${url.replace(/\/$/, '')}/api/v1/did/${encodeURIComponent(did)}`;
      const response = await fetch(endpoint, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'astracipher-core/0.1.0',
        },
      });

      if (response.status === 404) {
        return null;
      }

      if (response.status === 410) {
        // DID has been deactivated
        return null;
      }

      if (!response.ok) {
        const body = await response.text().catch(() => '');
        throw new Error(
          `Registry returned ${response.status}: ${body || response.statusText}`
        );
      }

      const data = await response.json() as { did?: DIDDocument; didDocument?: DIDDocument };
      // Server may return { did: DIDDocument } or { didDocument: DIDDocument }
      const didDocument = data.did || data.didDocument || (data as unknown as DIDDocument);

      if (!didDocument || !didDocument.id) {
        return null;
      }

      // HIGH-1 FIX: Verify the resolved DID document's self-signature
      // Prevents MITM or registry tampering from injecting a forged document.
      if (didDocument.proof) {
        const isValid = await this.verifyDID(didDocument);
        if (!isValid) {
          throw new Error(
            `DID document for ${did} failed signature verification — ` +
            'the document may have been tampered with'
          );
        }
      }

      // Verify the resolved DID matches the requested DID (prevents substitution)
      if (didDocument.id !== did) {
        throw new Error(
          `DID mismatch: requested ${did} but registry returned ${didDocument.id}`
        );
      }

      return didDocument;
    } catch (error) {
      if (error instanceof TypeError && (error.message.includes('fetch') || error.message.includes('ECONNREFUSED'))) {
        console.warn(
          `Could not connect to DID registry at ${url}. ` +
            'Ensure the AstraCipher server is running.'
        );
        return null;
      }
      throw error;
    }
  }

  /**
   * Update a DID document (add/remove keys, services, etc.)
   */
  async updateDID(
    didDocument: DIDDocument,
    updates: Partial<Pick<DIDDocument, 'service' | 'controller'>>,
    signingKeys: HybridKeyPair | KeyPair
  ): Promise<DIDDocument> {
    const updated = {
      ...didDocument,
      ...updates,
      updated: new Date().toISOString(),
    };

    // Remove old proof and re-sign
    delete (updated as Partial<DIDDocument>).proof;
    const proof = await this.crypto.signJSON(
      updated as unknown as Record<string, unknown>,
      signingKeys
    );
    updated.proof = proof;

    return updated;
  }

  /**
   * Deactivate a DID (mark as inactive)
   */
  async deactivateDID(
    didDocument: DIDDocument,
    signingKeys: HybridKeyPair | KeyPair
  ): Promise<DIDDocument> {
    return this.updateDID(
      { ...didDocument, deactivated: true },
      {},
      signingKeys
    );
  }

  /**
   * Verify a DID document's self-signature
   */
  async verifyDID(didDocument: DIDDocument): Promise<boolean> {
    if (!didDocument.proof) {
      return false;
    }

    // Extract public keys from verification methods
    const pqcMethod = didDocument.verificationMethod.find(
      (vm) => vm.type === 'ML-DSA-65-2024'
    );
    const classicalMethod = didDocument.verificationMethod.find(
      (vm) => vm.type === 'EcdsaSecp256r1VerificationKey2019'
    );

    const docWithoutProof = { ...didDocument };
    delete (docWithoutProof as Partial<DIDDocument>).proof;

    const publicKeys: {
      pqcPublicKey?: Uint8Array;
      classicalPublicKey?: Uint8Array;
    } = {};

    if (pqcMethod?.publicKeyMultibase) {
      publicKeys.pqcPublicKey = decodeMultibase(pqcMethod.publicKeyMultibase);
    }

    if (classicalMethod?.publicKeyMultibase) {
      publicKeys.classicalPublicKey = decodeMultibase(classicalMethod.publicKeyMultibase);
    }

    const result = await this.crypto.verifyJSON(
      docWithoutProof as unknown as Record<string, unknown>,
      didDocument.proof,
      publicKeys
    );

    return result.valid;
  }
}
