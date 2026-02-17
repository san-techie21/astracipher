/**
 * Trust Chain Verification for AgentPass
 *
 * Verifies the complete chain of trust:
 * Creator → Authorizer → Agent → Actions
 *
 * Each link in the chain is a signed assertion that can be independently verified.
 */

import {
  AgentPassCrypto,
  type HybridKeyPair,
  type KeyPair,
  type SignatureResult,
} from '@agentpass/crypto';
import type { AgentCredential } from '../credentials/credential-manager.js';

export interface TrustChainLink {
  /** The DID of the entity in this link */
  did: string;
  /** Role in the chain */
  role: 'creator' | 'authorizer' | 'agent' | 'sub-agent';
  /** The credential that establishes this link */
  credential?: AgentCredential;
  /** Signature from the parent link authorizing this entity */
  authorization?: SignatureResult;
  /** Timestamp of this link */
  timestamp: string;
  /** Delegation depth (0 = root) */
  depth: number;
  /** Maximum depth this entity can delegate to */
  maxDelegationDepth: number;
}

export interface TrustChainVerification {
  /** Whether the entire chain is valid */
  valid: boolean;
  /** The chain of trust from root to leaf */
  chain: TrustChainLink[];
  /** Total chain depth */
  depth: number;
  /** Maximum allowed depth */
  maxDepth: number;
  /** Errors found during verification */
  errors: string[];
  /** Warnings (non-fatal) */
  warnings: string[];
  /** Verification timestamp */
  verifiedAt: string;
}

export class TrustChain {
  private crypto: AgentPassCrypto;
  private maxChainDepth: number;

  constructor(options?: { crypto?: AgentPassCrypto; maxChainDepth?: number }) {
    this.crypto = options?.crypto || new AgentPassCrypto();
    this.maxChainDepth = options?.maxChainDepth || 5;
  }

  /**
   * Create the root of a trust chain (organization/creator)
   */
  async createRoot(
    creatorDID: string,
    creatorKeys: HybridKeyPair | KeyPair,
    options?: { maxDelegationDepth?: number }
  ): Promise<TrustChainLink> {
    const link: TrustChainLink = {
      did: creatorDID,
      role: 'creator',
      timestamp: new Date().toISOString(),
      depth: 0,
      maxDelegationDepth: options?.maxDelegationDepth || this.maxChainDepth,
    };

    // Self-sign the root
    link.authorization = await this.crypto.signJSON(
      link as unknown as Record<string, unknown>,
      creatorKeys
    );

    return link;
  }

  /**
   * Add a link to the trust chain (delegate authority)
   */
  async addLink(
    parentLink: TrustChainLink,
    childDID: string,
    childRole: TrustChainLink['role'],
    credential: AgentCredential,
    parentKeys: HybridKeyPair | KeyPair
  ): Promise<TrustChainLink> {
    const newDepth = parentLink.depth + 1;

    // Check delegation depth
    if (newDepth > parentLink.maxDelegationDepth) {
      throw new Error(
        `Delegation depth exceeded: ${newDepth} > ${parentLink.maxDelegationDepth}`
      );
    }

    if (newDepth > this.maxChainDepth) {
      throw new Error(
        `Maximum chain depth exceeded: ${newDepth} > ${this.maxChainDepth}`
      );
    }

    const link: TrustChainLink = {
      did: childDID,
      role: childRole,
      credential,
      timestamp: new Date().toISOString(),
      depth: newDepth,
      maxDelegationDepth: Math.min(
        parentLink.maxDelegationDepth,
        credential.credentialSubject.trustLevel
      ),
    };

    // Parent signs the new link
    link.authorization = await this.crypto.signJSON(
      {
        parentDID: parentLink.did,
        childDID,
        role: childRole,
        depth: newDepth,
        credentialId: credential.id,
        timestamp: link.timestamp,
      } as Record<string, unknown>,
      parentKeys
    );

    return link;
  }

  /**
   * Verify a complete trust chain
   */
  async verifyChain(
    chain: TrustChainLink[],
    publicKeyResolver: (
      did: string
    ) => Promise<{
      pqcPublicKey?: Uint8Array;
      classicalPublicKey?: Uint8Array;
    } | null>
  ): Promise<TrustChainVerification> {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (chain.length === 0) {
      return {
        valid: false,
        chain,
        depth: 0,
        maxDepth: this.maxChainDepth,
        errors: ['Empty trust chain'],
        warnings: [],
        verifiedAt: new Date().toISOString(),
      };
    }

    // Verify root
    if (chain[0].role !== 'creator') {
      errors.push(`First link must be creator, got ${chain[0].role}`);
    }

    if (chain[0].depth !== 0) {
      errors.push(`Root depth must be 0, got ${chain[0].depth}`);
    }

    // Verify each link
    for (let i = 0; i < chain.length; i++) {
      const link = chain[i];

      // Check depth consistency
      if (link.depth !== i) {
        errors.push(
          `Link ${i}: expected depth ${i}, got ${link.depth}`
        );
      }

      // Check maximum chain depth
      if (link.depth > this.maxChainDepth) {
        errors.push(
          `Link ${i}: depth ${link.depth} exceeds max ${this.maxChainDepth}`
        );
      }

      // Verify authorization signature
      if (link.authorization && i > 0) {
        const parentDID = chain[i - 1].did;
        const parentKeys = await publicKeyResolver(parentDID);

        if (!parentKeys) {
          errors.push(
            `Link ${i}: cannot resolve public keys for parent ${parentDID}`
          );
          continue;
        }

        const result = await this.crypto.verify(
          JSON.stringify({
            parentDID,
            childDID: link.did,
            role: link.role,
            depth: link.depth,
            credentialId: link.credential?.id,
            timestamp: link.timestamp,
          }),
          link.authorization,
          parentKeys
        );

        if (!result.valid) {
          errors.push(
            `Link ${i}: authorization signature invalid (${result.error})`
          );
        }
      }

      // Check credential expiration
      if (link.credential) {
        const expiration = new Date(link.credential.expirationDate);
        if (expiration < new Date()) {
          errors.push(
            `Link ${i}: credential expired on ${link.credential.expirationDate}`
          );
        }
      }

      // Delegation depth check
      if (i > 0) {
        const parentMaxDelegation = chain[i - 1].maxDelegationDepth;
        if (link.depth > parentMaxDelegation) {
          errors.push(
            `Link ${i}: delegation depth ${link.depth} exceeds parent's max ${parentMaxDelegation}`
          );
        }
      }
    }

    // Check for circular references
    const seenDIDs = new Set<string>();
    for (const link of chain) {
      if (seenDIDs.has(link.did)) {
        warnings.push(`Circular reference detected: ${link.did} appears multiple times`);
      }
      seenDIDs.add(link.did);
    }

    return {
      valid: errors.length === 0,
      chain,
      depth: chain.length - 1,
      maxDepth: this.maxChainDepth,
      errors,
      warnings,
      verifiedAt: new Date().toISOString(),
    };
  }

  /**
   * Get the effective permissions by walking up the chain
   * Each level can only have <= permissions of its parent.
   */
  getEffectivePermissions(chain: TrustChainLink[]): string[] {
    if (chain.length === 0) return [];

    let capabilities: Set<string> | null = null;

    for (const link of chain) {
      if (link.credential) {
        const linkCapabilities = new Set(
          link.credential.credentialSubject.capabilities
        );

        if (capabilities === null) {
          capabilities = linkCapabilities;
        } else {
          // Intersection — child can only have capabilities the parent granted
          capabilities = new Set(
            [...capabilities].filter((c) => linkCapabilities.has(c))
          );
        }
      }
    }

    return capabilities ? [...capabilities] : [];
  }
}
