/**
 * AgentPass - High-Level Client API
 *
 * The main entry point for developers using AgentPass.
 * Provides a simple, intuitive API for all protocol operations.
 *
 * Usage:
 *   const ap = new AgentPass({ network: 'mainnet' });
 *   const { did, keys } = await ap.createAgent({ name: 'MyAgent' });
 *   const credential = await ap.issueCredential({ ... });
 *   const result = await ap.verifyAgent(credential);
 */

import { AgentPassCrypto, type HybridKeyPair, type KeyPair, type CryptoConfig } from '@agentpass/crypto';
import { DIDManager, type DIDDocument, type DIDService, type DIDManagerOptions } from './did/did-manager.js';
import {
  CredentialManager,
  type AgentCredential,
  type IssueCredentialOptions,
  type AgentPermission,
} from './credentials/credential-manager.js';
import { TrustChain, type TrustChainLink, type TrustChainVerification } from './trust-chain/trust-chain.js';

export interface AgentPassConfig {
  /** Network: mainnet, testnet, local */
  network?: string;
  /** Registry URL for DID resolution */
  registryUrl?: string;
  /** Crypto configuration */
  crypto?: Partial<CryptoConfig>;
  /** Maximum trust chain depth */
  maxChainDepth?: number;
}

export class AgentPass {
  private config: AgentPassConfig;
  private crypto: AgentPassCrypto;
  private didManager: DIDManager;
  private credentialManager: CredentialManager;
  private trustChain: TrustChain;

  constructor(config: AgentPassConfig = {}) {
    this.config = {
      network: 'mainnet',
      registryUrl: 'https://registry.agentpass.dev',
      ...config,
    };

    this.crypto = new AgentPassCrypto(config.crypto);
    this.didManager = new DIDManager({
      crypto: this.crypto,
      registryUrl: this.config.registryUrl,
    });
    this.credentialManager = new CredentialManager(this.crypto);
    this.trustChain = new TrustChain({
      crypto: this.crypto,
      maxChainDepth: config.maxChainDepth,
    });
  }

  // ========================
  // Identity Operations
  // ========================

  /**
   * Create a new agent identity (DID + keys)
   */
  async createAgent(options: {
    name: string;
    description?: string;
    controller?: string;
    services?: DIDService[];
  }): Promise<{
    did: DIDDocument;
    keys: HybridKeyPair | KeyPair;
    didId: string;
  }> {
    const result = await this.didManager.createDID({
      network: this.config.network,
      controller: options.controller,
      services: options.services,
    });

    return {
      ...result,
      didId: result.did.id,
    };
  }

  /**
   * Resolve a DID to its document
   */
  async resolveAgent(didId: string): Promise<DIDDocument | null> {
    return this.didManager.resolveDID(didId);
  }

  /**
   * Verify a DID document's integrity
   */
  async verifyDID(did: DIDDocument): Promise<boolean> {
    return this.didManager.verifyDID(did);
  }

  // ========================
  // Credential Operations
  // ========================

  /**
   * Issue a credential for an agent
   */
  async issueCredential(
    options: {
      issuerDID: string;
      agentDID: string;
      name: string;
      description?: string;
      model?: string;
      version?: string;
      capabilities: string[];
      permissions: AgentPermission[];
      trustLevel?: number;
      validForDays?: number;
      rateLimits?: {
        requestsPerMinute?: number;
        requestsPerHour?: number;
        requestsPerDay?: number;
      };
      compliance?: Record<string, unknown>;
    },
    issuerKeys: HybridKeyPair | KeyPair
  ): Promise<AgentCredential> {
    return this.credentialManager.issueCredential(
      {
        issuerDID: options.issuerDID,
        subjectDID: options.agentDID,
        agent: {
          name: options.name,
          description: options.description,
          model: options.model,
          version: options.version,
        },
        capabilities: options.capabilities,
        permissions: options.permissions,
        trustLevel: options.trustLevel,
        validFor: (options.validForDays || 365) * 86400,
        rateLimits: options.rateLimits,
        compliance: options.compliance,
      },
      issuerKeys
    );
  }

  /**
   * Verify a credential.
   *
   * MED-2 FIX: If no public keys are supplied, attempt to resolve
   * the issuer DID and extract keys from the DID document.
   * This ensures the verification keys are cryptographically bound
   * to the issuer identity, not caller-supplied.
   */
  async verifyCredential(
    credential: AgentCredential,
    issuerPublicKeys?: {
      pqcPublicKey?: Uint8Array;
      classicalPublicKey?: Uint8Array;
    }
  ) {
    let keys = issuerPublicKeys;

    // MED-2 FIX: If no keys provided, resolve from issuer DID
    if (!keys || (!keys.pqcPublicKey && !keys.classicalPublicKey)) {
      const issuerDID = credential.issuer;
      const issuerDoc = await this.didManager.resolveDID(issuerDID);
      if (issuerDoc) {
        keys = this.extractPublicKeysFromDID(issuerDoc);
      }
    }

    if (!keys || (!keys.pqcPublicKey && !keys.classicalPublicKey)) {
      return {
        valid: false,
        expired: new Date(credential.expirationDate) < new Date(),
        signatureValid: false,
        errors: ['No public keys available for verification — could not resolve issuer DID'],
      };
    }

    return this.credentialManager.verifyCredential(credential, keys);
  }

  /**
   * Extract public keys from a resolved DID document.
   */
  private extractPublicKeysFromDID(didDoc: DIDDocument): {
    pqcPublicKey?: Uint8Array;
    classicalPublicKey?: Uint8Array;
  } {
    const keys: { pqcPublicKey?: Uint8Array; classicalPublicKey?: Uint8Array } = {};

    for (const vm of didDoc.verificationMethod || []) {
      if (!vm.publicKeyMultibase) continue;
      const prefix = vm.publicKeyMultibase[0];
      const data = vm.publicKeyMultibase.slice(1);
      let decoded: Uint8Array;
      if (prefix === 'u') {
        decoded = new Uint8Array(Buffer.from(data, 'base64url'));
      } else if (prefix === 'z') {
        decoded = new Uint8Array(Buffer.from(data, 'base64')); // legacy compat
      } else {
        continue;
      }

      if (vm.type === 'ML-DSA-65-2024') {
        keys.pqcPublicKey = decoded;
      } else if (vm.type === 'EcdsaSecp256r1VerificationKey2019') {
        keys.classicalPublicKey = decoded;
      }
    }

    return keys;
  }

  /**
   * Check if an agent has a capability
   */
  hasCapability(credential: AgentCredential, capability: string): boolean {
    return this.credentialManager.hasCapability(credential, capability);
  }

  /**
   * Check if an agent has permission
   */
  hasPermission(
    credential: AgentCredential,
    resource: string,
    action: AgentPermission['actions'][number]
  ): boolean {
    return this.credentialManager.hasPermission(credential, resource, action);
  }

  // ========================
  // Trust Chain Operations
  // ========================

  /**
   * Create a trust chain root
   */
  async createTrustRoot(
    creatorDID: string,
    creatorKeys: HybridKeyPair | KeyPair
  ): Promise<TrustChainLink> {
    return this.trustChain.createRoot(creatorDID, creatorKeys);
  }

  /**
   * Delegate trust to a child agent
   */
  async delegateTrust(
    parentLink: TrustChainLink,
    childDID: string,
    credential: AgentCredential,
    parentKeys: HybridKeyPair | KeyPair,
    role: TrustChainLink['role'] = 'agent'
  ): Promise<TrustChainLink> {
    return this.trustChain.addLink(
      parentLink,
      childDID,
      role,
      credential,
      parentKeys
    );
  }

  /**
   * Verify a complete trust chain
   */
  async verifyTrustChain(
    chain: TrustChainLink[],
    publicKeyResolver: (
      did: string
    ) => Promise<{
      pqcPublicKey?: Uint8Array;
      classicalPublicKey?: Uint8Array;
    } | null>
  ): Promise<TrustChainVerification> {
    return this.trustChain.verifyChain(chain, publicKeyResolver);
  }

  // ========================
  // Utility
  // ========================

  /**
   * Get protocol version info
   */
  getVersion(): { protocol: string; sdk: string; crypto: string } {
    return {
      protocol: '0.1.0',
      sdk: '0.1.0',
      crypto: this.crypto.getConfig().mode,
    };
  }
}
