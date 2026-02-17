/**
 * DID (Decentralized Identifier) Manager
 *
 * Implements W3C DID v1.1 with the did:agentpass method.
 * Each AI agent gets a unique DID that serves as its identity anchor.
 *
 * DID format: did:agentpass:<network>:<unique-id>
 * Example:    did:agentpass:mainnet:a1b2c3d4e5f6
 */

import { v4 as uuidv4 } from 'uuid';
import {
  AgentPassCrypto,
  type HybridKeyPair,
  type KeyPair,
  type SignatureResult,
} from '@agentpass/crypto';

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

export class DIDManager {
  private crypto: AgentPassCrypto;

  constructor(crypto?: AgentPassCrypto) {
    this.crypto = crypto || new AgentPassCrypto();
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
    const didId = `did:agentpass:${network}:${uniqueId}`;

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
        publicKeyMultibase: `z${Buffer.from(hybrid.pqc.publicKey).toString('base64')}`,
      });
      authenticationIds.push(pqcMethodId);
      assertionMethodIds.push(pqcMethodId);

      // Classical verification method
      const classicalMethodId = `${didId}#key-classical-1`;
      verificationMethods.push({
        id: classicalMethodId,
        type: 'EcdsaSecp256r1VerificationKey2019',
        controller: didId,
        publicKeyMultibase: `z${Buffer.from(hybrid.classical.publicKey).toString('base64')}`,
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
        publicKeyMultibase: `z${Buffer.from(single.publicKey).toString('base64')}`,
      });
      authenticationIds.push(methodId);
      assertionMethodIds.push(methodId);
    }

    // Build DID document
    const didDocument: DIDDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1',
        'https://agentpass.dev/ns/v1',
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
   * Resolve a DID to its document (placeholder — needs registry integration)
   */
  async resolveDID(did: string): Promise<DIDDocument | null> {
    // Validate DID format
    if (!did.startsWith('did:agentpass:')) {
      throw new Error(
        `Invalid DID method: expected did:agentpass:*, got ${did}`
      );
    }

    // In production, this queries the DID registry
    // For now, return null (not found)
    console.warn(
      `DID resolution for ${did} requires a registry connection. ` +
        'Use AgentPass server or self-hosted registry.'
    );
    return null;
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
      const b64 = pqcMethod.publicKeyMultibase.slice(1); // remove 'z' prefix
      publicKeys.pqcPublicKey = new Uint8Array(Buffer.from(b64, 'base64'));
    }

    if (classicalMethod?.publicKeyMultibase) {
      const b64 = classicalMethod.publicKeyMultibase.slice(1);
      publicKeys.classicalPublicKey = new Uint8Array(
        Buffer.from(b64, 'base64')
      );
    }

    const result = await this.crypto.verifyJSON(
      docWithoutProof as unknown as Record<string, unknown>,
      didDocument.proof,
      publicKeys
    );

    return result.valid;
  }
}
