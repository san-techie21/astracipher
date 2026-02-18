/**
 * Verifiable Credential Manager for AstraCipher
 *
 * Issues, verifies, and revokes W3C Verifiable Credentials
 * that attest to an AI agent's identity, capabilities, and permissions.
 */

import { v4 as uuidv4 } from 'uuid';
import {
  AstraCipherCrypto,
  type HybridKeyPair,
  type KeyPair,
  type SignatureResult,
} from '@astracipher/crypto';

export interface CredentialSubject {
  /** The agent's DID */
  id: string;
  /** Agent name */
  name: string;
  /** Agent description */
  description?: string;
  /** Model/framework the agent is built on */
  model?: string;
  /** Agent version */
  version?: string;
  /** Allowed operations/capabilities */
  capabilities: string[];
  /** Resource access permissions */
  permissions: AgentPermission[];
  /** Maximum trust level (1-10) */
  trustLevel: number;
  /** Rate limits */
  rateLimits?: {
    requestsPerMinute?: number;
    requestsPerHour?: number;
    requestsPerDay?: number;
  };
  /** Compliance metadata (framework-specific) */
  compliance?: Record<string, unknown>;
}

export interface AgentPermission {
  /** Resource being accessed */
  resource: string;
  /** Allowed actions on the resource */
  actions: ('read' | 'write' | 'execute' | 'delete' | 'admin')[];
  /** Conditions that must be met */
  conditions?: Record<string, unknown>;
  /** Expiration for this specific permission */
  expiresAt?: string;
}

export interface CredentialProof {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  signature: SignatureResult;
}

export interface CredentialStatus {
  id: string;
  type: 'AstraCipherRevocationList2026';
  revocationListIndex: string;
  revocationListCredential: string;
}

export interface AgentCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate: string;
  /** HIGH-7 FIX: Unique nonce for replay protection */
  nonce: string;
  credentialSubject: CredentialSubject;
  credentialStatus?: CredentialStatus;
  proof?: CredentialProof;
}

export interface IssueCredentialOptions {
  /** Issuer's DID */
  issuerDID: string;
  /** Subject agent's DID */
  subjectDID: string;
  /** Agent details */
  agent: {
    name: string;
    description?: string;
    model?: string;
    version?: string;
  };
  /** What the agent can do */
  capabilities: string[];
  /** Resource permissions */
  permissions: AgentPermission[];
  /** Trust level 1-10 */
  trustLevel?: number;
  /** How long the credential is valid (in seconds) */
  validFor?: number;
  /** Rate limits */
  rateLimits?: CredentialSubject['rateLimits'];
  /** Compliance metadata */
  compliance?: Record<string, unknown>;
}

export class CredentialManager {
  private crypto: AstraCipherCrypto;

  constructor(crypto?: AstraCipherCrypto) {
    this.crypto = crypto || new AstraCipherCrypto();
  }

  /**
   * Issue a new verifiable credential for an agent
   */
  /**
   * MED-5: Maximum credential validity = 5 years (prevents century-long credentials)
   */
  static readonly MAX_VALIDITY_SECONDS = 86400 * 365 * 5; // 5 years

  async issueCredential(
    options: IssueCredentialOptions,
    issuerKeys: HybridKeyPair | KeyPair
  ): Promise<AgentCredential> {
    const credentialId = `urn:astracipher:credential:${uuidv4()}`;
    const now = new Date();
    const requestedValidity = options.validFor || 86400 * 365; // 1 year default
    // MED-5 FIX: Cap validity at MAX_VALIDITY_SECONDS
    const validFor = Math.min(requestedValidity, CredentialManager.MAX_VALIDITY_SECONDS);
    const expirationDate = new Date(now.getTime() + validFor * 1000);

    const credential: AgentCredential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://astracipher.com/ns/credentials/v1',
      ],
      id: credentialId,
      type: ['VerifiableCredential', 'AgentIdentityCredential'],
      issuer: options.issuerDID,
      issuanceDate: now.toISOString(),
      expirationDate: expirationDate.toISOString(),
      // HIGH-7 FIX: Unique nonce prevents replay attacks
      nonce: uuidv4(),
      credentialSubject: {
        id: options.subjectDID,
        name: options.agent.name,
        description: options.agent.description,
        model: options.agent.model,
        version: options.agent.version,
        capabilities: options.capabilities,
        permissions: options.permissions,
        trustLevel: options.trustLevel || 5,
        rateLimits: options.rateLimits,
        compliance: options.compliance,
      },
      credentialStatus: {
        id: `https://registry.astracipher.com/revocation/${credentialId}`,
        type: 'AstraCipherRevocationList2026',
        revocationListIndex: '0',
        revocationListCredential: `https://registry.astracipher.com/revocation-list/${options.issuerDID}`,
      },
    };

    // Sign the credential
    const signature = await this.crypto.signJSON(
      credential as unknown as Record<string, unknown>,
      issuerKeys
    );

    credential.proof = {
      type: 'AstraCipherHybridSignature2026',
      created: now.toISOString(),
      verificationMethod: `${options.issuerDID}#key-pqc-1`,
      proofPurpose: 'assertionMethod',
      signature,
    };

    return credential;
  }

  /**
   * Verify a credential's signature and validity
   */
  async verifyCredential(
    credential: AgentCredential,
    issuerPublicKeys: {
      pqcPublicKey?: Uint8Array;
      classicalPublicKey?: Uint8Array;
    }
  ): Promise<{
    valid: boolean;
    expired: boolean;
    signatureValid: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];

    // Check expiration
    const now = new Date();
    const expirationDate = new Date(credential.expirationDate);
    const expired = now > expirationDate;
    if (expired) {
      errors.push(
        `Credential expired on ${credential.expirationDate}`
      );
    }

    // Check issuance date is in the past
    const issuanceDate = new Date(credential.issuanceDate);
    if (issuanceDate > now) {
      errors.push(
        `Credential not yet valid (issuance: ${credential.issuanceDate})`
      );
    }

    // Verify signature
    let signatureValid = false;
    if (credential.proof?.signature) {
      const credWithoutProof = { ...credential };
      delete (credWithoutProof as Partial<AgentCredential>).proof;

      const result = await this.crypto.verifyJSON(
        credWithoutProof as unknown as Record<string, unknown>,
        credential.proof.signature,
        issuerPublicKeys
      );
      signatureValid = result.valid;

      if (!signatureValid) {
        errors.push(
          `Signature verification failed: ${result.error || 'unknown'}`
        );
      }
    } else {
      errors.push('Credential has no proof/signature');
    }

    return {
      valid: signatureValid && !expired && errors.length === 0,
      expired,
      signatureValid,
      errors,
    };
  }

  /**
   * Check if an agent has a specific capability
   */
  hasCapability(credential: AgentCredential, capability: string): boolean {
    return credential.credentialSubject.capabilities.includes(capability);
  }

  /**
   * Check if an agent has permission for a resource/action
   */
  hasPermission(
    credential: AgentCredential,
    resource: string,
    action: AgentPermission['actions'][number]
  ): boolean {
    return credential.credentialSubject.permissions.some(
      (perm) =>
        this.matchResource(perm.resource, resource) &&
        perm.actions.includes(action) &&
        (!perm.expiresAt || new Date(perm.expiresAt) > new Date())
    );
  }

  /**
   * Match a resource pattern against a specific resource path.
   * Supports glob-style wildcards:
   *   '*' matches everything
   *   'api/*' matches 'api/users', 'api/orders', 'api/orders/123', etc.
   *   'api/orders/*' matches 'api/orders/123' but not 'api/users'
   */
  private matchResource(pattern: string, resource: string): boolean {
    if (pattern === '*' || pattern === resource) return true;
    if (pattern.endsWith('/*')) {
      const prefix = pattern.slice(0, -2); // remove /*
      return resource === prefix || resource.startsWith(prefix + '/');
    }
    if (pattern.endsWith('*')) {
      const prefix = pattern.slice(0, -1); // remove *
      return resource.startsWith(prefix);
    }
    return false;
  }

  /**
   * Create a presentation (subset of credential for sharing)
   */
  async createPresentation(
    credentials: AgentCredential[],
    holderDID: string,
    holderKeys: HybridKeyPair | KeyPair
  ): Promise<Record<string, unknown>> {
    const presentation = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://astracipher.com/ns/credentials/v1',
      ],
      type: ['VerifiablePresentation', 'AgentIdentityPresentation'],
      holder: holderDID,
      verifiableCredential: credentials,
      created: new Date().toISOString(),
    };

    const signature = await this.crypto.signJSON(
      presentation as unknown as Record<string, unknown>,
      holderKeys
    );

    return {
      ...presentation,
      proof: {
        type: 'AstraCipherHybridSignature2026',
        created: new Date().toISOString(),
        verificationMethod: `${holderDID}#key-pqc-1`,
        proofPurpose: 'authentication',
        signature,
      },
    };
  }
}
