/**
 * Comprehensive tests for @astracipher/core
 *
 * Tests the full AstraCipher protocol:
 * - DID creation, verification, deactivation
 * - Verifiable Credential issuance, verification, capabilities
 * - Trust Chain creation, delegation, verification
 * - AstraCipher high-level API
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { AstraCipherCrypto, type HybridKeyPair } from '@astracipher/crypto';
import { DIDManager, type DIDDocument } from './did/did-manager.js';
import { CredentialManager, type AgentCredential, type AgentPermission } from './credentials/credential-manager.js';
import { TrustChain, type TrustChainLink } from './trust-chain/trust-chain.js';
import { AstraCipher } from './astra-cipher.js';

// ============================
// DID Manager Tests
// ============================

describe('DIDManager', () => {
  let didManager: DIDManager;
  let crypto: AstraCipherCrypto;

  beforeEach(() => {
    crypto = new AstraCipherCrypto();
    didManager = new DIDManager({ crypto });
  });

  describe('createDID', () => {
    it('should create a valid DID document', async () => {
      const { did, keys } = await didManager.createDID({ network: 'testnet' });

      expect(did.id).toMatch(/^did:astracipher:testnet:/);
      expect(did['@context']).toContain('https://www.w3.org/ns/did/v1');
      expect(did['@context']).toContain('https://astracipher.com/ns/v1');
      expect(did.controller).toBe(did.id);
      expect(did.verificationMethod.length).toBeGreaterThan(0);
      expect(did.authentication.length).toBeGreaterThan(0);
      expect(did.assertionMethod.length).toBeGreaterThan(0);
      expect(did.created).toBeTruthy();
      expect(did.updated).toBeTruthy();
      expect(did.proof).toBeTruthy();
    });

    it('should create hybrid verification methods by default', async () => {
      const { did } = await didManager.createDID();

      const pqcMethod = did.verificationMethod.find(vm => vm.type === 'ML-DSA-65-2024');
      const classicalMethod = did.verificationMethod.find(vm => vm.type === 'EcdsaSecp256r1VerificationKey2019');

      expect(pqcMethod).toBeDefined();
      expect(classicalMethod).toBeDefined();
      // MED-1 FIX: Now uses 'u' prefix (base64url) instead of 'z' (base58btc)
      expect(pqcMethod!.publicKeyMultibase).toMatch(/^u/);
      expect(classicalMethod!.publicKeyMultibase).toMatch(/^u/);
    });

    it('should support custom controller DID', async () => {
      const controllerDID = 'did:astracipher:mainnet:controller123';
      const { did } = await didManager.createDID({ controller: controllerDID });

      expect(did.controller).toBe(controllerDID);
    });

    it('should support custom services', async () => {
      const services = [{
        id: 'did:astracipher:testnet:abc#api',
        type: 'AgentService',
        serviceEndpoint: 'https://api.example.com/agent',
        description: 'Agent API endpoint',
      }];

      const { did } = await didManager.createDID({ services });
      expect(did.service).toHaveLength(1);
      expect(did.service![0].type).toBe('AgentService');
    });

    it('should use mainnet by default', async () => {
      const { did } = await didManager.createDID();
      expect(did.id).toMatch(/^did:astracipher:mainnet:/);
    });
  });

  describe('verifyDID', () => {
    it('should verify a self-signed DID document', async () => {
      const { did } = await didManager.createDID({ network: 'testnet' });

      const isValid = await didManager.verifyDID(did);
      expect(isValid).toBe(true);
    });

    it('should reject a tampered DID document', async () => {
      const { did } = await didManager.createDID({ network: 'testnet' });

      // Tamper with the document
      const tampered = { ...did, updated: new Date().toISOString() };
      const isValid = await didManager.verifyDID(tampered);
      expect(isValid).toBe(false);
    });

    it('should reject a DID without proof', async () => {
      const { did } = await didManager.createDID({ network: 'testnet' });
      const noProof = { ...did };
      delete (noProof as Partial<DIDDocument>).proof;

      const isValid = await didManager.verifyDID(noProof);
      expect(isValid).toBe(false);
    });
  });

  describe('updateDID', () => {
    it('should update a DID document with new services', async () => {
      const { did, keys } = await didManager.createDID({ network: 'testnet' });

      const updated = await didManager.updateDID(did, {
        service: [{
          id: `${did.id}#messaging`,
          type: 'AgentMessaging',
          serviceEndpoint: 'wss://msg.example.com',
        }],
      }, keys);

      expect(updated.service).toHaveLength(1);
      expect(updated.updated).not.toBe(did.updated);
      expect(updated.proof).toBeTruthy();

      // New proof should be valid
      const isValid = await didManager.verifyDID(updated);
      expect(isValid).toBe(true);
    });
  });

  describe('deactivateDID', () => {
    it('should deactivate a DID document', async () => {
      const { did, keys } = await didManager.createDID({ network: 'testnet' });

      const deactivated = await didManager.deactivateDID(did, keys);
      expect(deactivated.deactivated).toBe(true);

      // Deactivated DID should still have valid proof
      const isValid = await didManager.verifyDID(deactivated);
      expect(isValid).toBe(true);
    });
  });

  describe('resolveDID', () => {
    it('should reject invalid DID format', async () => {
      await expect(didManager.resolveDID('invalid:did')).rejects.toThrow(
        'Invalid DID method'
      );
    });

    it('should return null without registry URL', async () => {
      const result = await didManager.resolveDID('did:astracipher:testnet:abc123');
      expect(result).toBeNull();
    });
  });
});

// ============================
// Credential Manager Tests
// ============================

describe('CredentialManager', () => {
  let credManager: CredentialManager;
  let crypto: AstraCipherCrypto;
  let issuerKeys: HybridKeyPair;
  let issuerDID: string;
  let agentDID: string;

  beforeEach(async () => {
    crypto = new AstraCipherCrypto();
    credManager = new CredentialManager(crypto);
    issuerKeys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
    issuerDID = 'did:astracipher:testnet:issuer-001';
    agentDID = 'did:astracipher:testnet:agent-001';
  });

  describe('issueCredential', () => {
    it('should issue a valid verifiable credential', async () => {
      const cred = await credManager.issueCredential(
        {
          issuerDID,
          subjectDID: agentDID,
          agent: { name: 'TestAgent', description: 'A test agent' },
          capabilities: ['read', 'write'],
          permissions: [{ resource: '*', actions: ['read', 'write'] }],
          trustLevel: 7,
          validFor: 86400 * 30, // 30 days
        },
        issuerKeys
      );

      expect(cred.id).toMatch(/^urn:astracipher:credential:/);
      expect(cred.type).toContain('VerifiableCredential');
      expect(cred.type).toContain('AgentIdentityCredential');
      expect(cred.issuer).toBe(issuerDID);
      expect(cred.credentialSubject.id).toBe(agentDID);
      expect(cred.credentialSubject.name).toBe('TestAgent');
      expect(cred.credentialSubject.capabilities).toEqual(['read', 'write']);
      expect(cred.credentialSubject.trustLevel).toBe(7);
      expect(cred.proof).toBeTruthy();
      expect(cred.proof!.type).toBe('AstraCipherHybridSignature2026');
    });

    it('should use default trust level of 5', async () => {
      const cred = await credManager.issueCredential(
        {
          issuerDID,
          subjectDID: agentDID,
          agent: { name: 'DefaultTrust' },
          capabilities: ['read'],
          permissions: [],
        },
        issuerKeys
      );

      expect(cred.credentialSubject.trustLevel).toBe(5);
    });

    it('should set valid expiration date', async () => {
      const now = new Date();
      const cred = await credManager.issueCredential(
        {
          issuerDID,
          subjectDID: agentDID,
          agent: { name: 'ExpirationTest' },
          capabilities: ['read'],
          permissions: [],
          validFor: 86400, // 1 day
        },
        issuerKeys
      );

      const issuance = new Date(cred.issuanceDate);
      const expiration = new Date(cred.expirationDate);

      expect(issuance.getTime()).toBeGreaterThanOrEqual(now.getTime() - 1000);
      expect(expiration.getTime() - issuance.getTime()).toBeCloseTo(86400 * 1000, -3);
    });

    it('should include credential status for revocation', async () => {
      const cred = await credManager.issueCredential(
        {
          issuerDID,
          subjectDID: agentDID,
          agent: { name: 'RevocationTest' },
          capabilities: ['read'],
          permissions: [],
        },
        issuerKeys
      );

      expect(cred.credentialStatus).toBeDefined();
      expect(cred.credentialStatus!.type).toBe('AstraCipherRevocationList2026');
    });
  });

  describe('verifyCredential', () => {
    it('should verify a valid credential', async () => {
      const cred = await credManager.issueCredential(
        {
          issuerDID,
          subjectDID: agentDID,
          agent: { name: 'VerifyTest' },
          capabilities: ['read'],
          permissions: [],
          validFor: 86400,
        },
        issuerKeys
      );

      const result = await credManager.verifyCredential(cred, {
        pqcPublicKey: issuerKeys.pqc.publicKey,
        classicalPublicKey: issuerKeys.classical.publicKey,
      });

      expect(result.valid).toBe(true);
      expect(result.signatureValid).toBe(true);
      expect(result.expired).toBe(false);
      expect(result.errors).toHaveLength(0);
    });

    it('should detect expired credentials', async () => {
      const cred = await credManager.issueCredential(
        {
          issuerDID,
          subjectDID: agentDID,
          agent: { name: 'ExpiredTest' },
          capabilities: ['read'],
          permissions: [],
          validFor: -1, // Already expired
        },
        issuerKeys
      );

      const result = await credManager.verifyCredential(cred, {
        pqcPublicKey: issuerKeys.pqc.publicKey,
        classicalPublicKey: issuerKeys.classical.publicKey,
      });

      expect(result.expired).toBe(true);
      expect(result.valid).toBe(false);
    });

    it('should detect invalid signatures', async () => {
      const cred = await credManager.issueCredential(
        {
          issuerDID,
          subjectDID: agentDID,
          agent: { name: 'BadSigTest' },
          capabilities: ['read'],
          permissions: [],
        },
        issuerKeys
      );

      // Verify with wrong keys
      const wrongKeys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
      const result = await credManager.verifyCredential(cred, {
        pqcPublicKey: wrongKeys.pqc.publicKey,
        classicalPublicKey: wrongKeys.classical.publicKey,
      });

      expect(result.signatureValid).toBe(false);
      expect(result.valid).toBe(false);
    });
  });

  describe('hasCapability', () => {
    it('should detect present capabilities', async () => {
      const cred = await credManager.issueCredential(
        {
          issuerDID,
          subjectDID: agentDID,
          agent: { name: 'CapabilityTest' },
          capabilities: ['read', 'write', 'execute'],
          permissions: [],
        },
        issuerKeys
      );

      expect(credManager.hasCapability(cred, 'read')).toBe(true);
      expect(credManager.hasCapability(cred, 'write')).toBe(true);
      expect(credManager.hasCapability(cred, 'delete')).toBe(false);
    });
  });

  describe('hasPermission', () => {
    it('should check resource-level permissions', async () => {
      const cred = await credManager.issueCredential(
        {
          issuerDID,
          subjectDID: agentDID,
          agent: { name: 'PermissionTest' },
          capabilities: ['database'],
          permissions: [
            { resource: 'database:users', actions: ['read', 'write'] },
            { resource: 'database:logs', actions: ['read'] },
          ],
        },
        issuerKeys
      );

      expect(credManager.hasPermission(cred, 'database:users', 'read')).toBe(true);
      expect(credManager.hasPermission(cred, 'database:users', 'write')).toBe(true);
      expect(credManager.hasPermission(cred, 'database:users', 'delete')).toBe(false);
      expect(credManager.hasPermission(cred, 'database:logs', 'read')).toBe(true);
      expect(credManager.hasPermission(cred, 'database:logs', 'write')).toBe(false);
    });

    it('should support wildcard permissions', async () => {
      const cred = await credManager.issueCredential(
        {
          issuerDID,
          subjectDID: agentDID,
          agent: { name: 'WildcardTest' },
          capabilities: ['admin'],
          permissions: [
            { resource: '*', actions: ['read', 'write', 'execute', 'delete', 'admin'] },
          ],
        },
        issuerKeys
      );

      expect(credManager.hasPermission(cred, 'any-resource', 'admin')).toBe(true);
      expect(credManager.hasPermission(cred, 'database:secret', 'delete')).toBe(true);
    });
  });

  describe('createPresentation', () => {
    it('should create a verifiable presentation', async () => {
      const cred = await credManager.issueCredential(
        {
          issuerDID,
          subjectDID: agentDID,
          agent: { name: 'PresentationTest' },
          capabilities: ['read'],
          permissions: [],
        },
        issuerKeys
      );

      const holderKeys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
      const presentation = await credManager.createPresentation([cred], agentDID, holderKeys);

      expect(presentation.type).toContain('VerifiablePresentation');
      expect(presentation.holder).toBe(agentDID);
      expect(presentation.proof).toBeTruthy();
      expect((presentation.verifiableCredential as AgentCredential[]).length).toBe(1);
    });
  });
});

// ============================
// Trust Chain Tests
// ============================

describe('TrustChain', () => {
  let trustChain: TrustChain;
  let crypto: AstraCipherCrypto;
  let credManager: CredentialManager;

  beforeEach(() => {
    crypto = new AstraCipherCrypto();
    trustChain = new TrustChain({ crypto, maxChainDepth: 5 });
    credManager = new CredentialManager(crypto);
  });

  describe('createRoot', () => {
    it('should create a trust chain root', async () => {
      const creatorKeys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
      const root = await trustChain.createRoot('did:astracipher:testnet:creator', creatorKeys);

      expect(root.did).toBe('did:astracipher:testnet:creator');
      expect(root.role).toBe('creator');
      expect(root.depth).toBe(0);
      expect(root.maxDelegationDepth).toBe(5);
      expect(root.authorization).toBeTruthy();
    });
  });

  describe('addLink', () => {
    it('should add a child link to the chain', async () => {
      const creatorKeys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
      const creatorDID = 'did:astracipher:testnet:creator';
      const agentDID = 'did:astracipher:testnet:agent';

      const root = await trustChain.createRoot(creatorDID, creatorKeys);

      const credential = await credManager.issueCredential(
        {
          issuerDID: creatorDID,
          subjectDID: agentDID,
          agent: { name: 'ChildAgent' },
          capabilities: ['read'],
          permissions: [{ resource: '*', actions: ['read'] }],
          trustLevel: 5,
        },
        creatorKeys
      );

      const child = await trustChain.addLink(root, agentDID, 'agent', credential, creatorKeys);

      expect(child.did).toBe(agentDID);
      expect(child.role).toBe('agent');
      expect(child.depth).toBe(1);
      expect(child.credential).toBeDefined();
      expect(child.authorization).toBeTruthy();
    });

    it('should reject delegation exceeding max depth', async () => {
      const limitedChain = new TrustChain({ crypto, maxChainDepth: 1 });
      const creatorKeys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
      const root = await limitedChain.createRoot('did:astracipher:testnet:creator', creatorKeys);

      const credential = await credManager.issueCredential(
        {
          issuerDID: 'did:astracipher:testnet:creator',
          subjectDID: 'did:astracipher:testnet:agent1',
          agent: { name: 'Agent1' },
          capabilities: ['read'],
          permissions: [],
          trustLevel: 5,
        },
        creatorKeys
      );

      const link1 = await limitedChain.addLink(root, 'did:astracipher:testnet:agent1', 'agent', credential, creatorKeys);

      // Second delegation should exceed depth
      await expect(
        limitedChain.addLink(link1, 'did:astracipher:testnet:agent2', 'sub-agent', credential, creatorKeys)
      ).rejects.toThrow('depth exceeded');
    });
  });

  describe('verifyChain', () => {
    it('should verify a valid chain', async () => {
      const creatorKeys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
      const creatorDID = 'did:astracipher:testnet:creator';

      const root = await trustChain.createRoot(creatorDID, creatorKeys);

      const credential = await credManager.issueCredential(
        {
          issuerDID: creatorDID,
          subjectDID: 'did:astracipher:testnet:agent',
          agent: { name: 'TrustedAgent' },
          capabilities: ['read'],
          permissions: [],
          trustLevel: 5,
          validFor: 86400,
        },
        creatorKeys
      );

      const agentLink = await trustChain.addLink(
        root, 'did:astracipher:testnet:agent', 'agent', credential, creatorKeys
      );

      const keyResolver = async (did: string) => {
        if (did === creatorDID) {
          return {
            pqcPublicKey: creatorKeys.pqc.publicKey,
            classicalPublicKey: creatorKeys.classical.publicKey,
          };
        }
        return null;
      };

      const result = await trustChain.verifyChain([root, agentLink], keyResolver);

      expect(result.valid).toBe(true);
      expect(result.depth).toBe(1);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject an empty chain', async () => {
      const result = await trustChain.verifyChain([], async () => null);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Empty trust chain');
    });

    it('should detect circular references', async () => {
      const creatorKeys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
      const creatorDID = 'did:astracipher:testnet:circular';

      const root = await trustChain.createRoot(creatorDID, creatorKeys);

      // Create a fake second link with the same DID (circular)
      const duplicateLink: TrustChainLink = {
        ...root,
        depth: 1,
        role: 'agent',
      };

      const result = await trustChain.verifyChain([root, duplicateLink], async () => ({
        pqcPublicKey: creatorKeys.pqc.publicKey,
        classicalPublicKey: creatorKeys.classical.publicKey,
      }));

      // HIGH-3 FIX: Circular references are now errors, not warnings
      expect(result.errors.some(e => e.includes('Circular reference'))).toBe(true);
      expect(result.valid).toBe(false);
    });
  });

  describe('getEffectivePermissions', () => {
    it('should compute intersection of capabilities across chain', async () => {
      const creatorKeys = (await crypto.generateIdentityKeys()) as HybridKeyPair;
      const creatorDID = 'did:astracipher:testnet:creator';

      const root = await trustChain.createRoot(creatorDID, creatorKeys);

      const cred1 = await credManager.issueCredential(
        {
          issuerDID: creatorDID,
          subjectDID: 'did:astracipher:testnet:auth',
          agent: { name: 'Authorizer' },
          capabilities: ['read', 'write', 'execute'],
          permissions: [],
          trustLevel: 7,
        },
        creatorKeys
      );

      const authLink = await trustChain.addLink(root, 'did:astracipher:testnet:auth', 'authorizer', cred1, creatorKeys);

      const cred2 = await credManager.issueCredential(
        {
          issuerDID: 'did:astracipher:testnet:auth',
          subjectDID: 'did:astracipher:testnet:agent',
          agent: { name: 'Agent' },
          capabilities: ['read', 'write'], // Subset of parent
          permissions: [],
          trustLevel: 5,
        },
        creatorKeys
      );

      const agentLink = await trustChain.addLink(authLink, 'did:astracipher:testnet:agent', 'agent', cred2, creatorKeys);

      const permissions = trustChain.getEffectivePermissions([root, authLink, agentLink]);

      // Should be intersection: ['read', 'write']
      expect(permissions).toContain('read');
      expect(permissions).toContain('write');
      expect(permissions).not.toContain('execute');
    });
  });
});

// ============================
// AstraCipher (High-Level API) Tests
// ============================

describe('AstraCipher', () => {
  let ap: AstraCipher;

  beforeEach(() => {
    ap = new AstraCipher({ network: 'testnet' });
  });

  it('should return protocol version info', () => {
    const version = ap.getVersion();
    expect(version.protocol).toBe('0.1.0');
    expect(version.sdk).toBe('0.1.0');
    expect(version.crypto).toBe('hybrid');
  });

  it('should create an agent with DID and keys', async () => {
    const result = await ap.createAgent({
      name: 'IntegrationTestAgent',
      description: 'An agent for integration testing',
    });

    expect(result.did).toBeDefined();
    expect(result.keys).toBeDefined();
    expect(result.didId).toMatch(/^did:astracipher:testnet:/);
    expect(result.did.id).toBe(result.didId);
  });

  it('should verify an agent DID', async () => {
    const { did } = await ap.createAgent({ name: 'VerifyTest' });
    const isValid = await ap.verifyDID(did);
    expect(isValid).toBe(true);
  });

  it('should issue and verify credentials end-to-end', async () => {
    const { did: issuerDID, keys: issuerKeys, didId: issuerId } = await ap.createAgent({ name: 'Issuer' });
    const { didId: agentId } = await ap.createAgent({ name: 'Agent' });

    const credential = await ap.issueCredential(
      {
        issuerDID: issuerId,
        agentDID: agentId,
        name: 'E2E-Agent',
        capabilities: ['read', 'write'],
        permissions: [{ resource: '*', actions: ['read', 'write'] }],
        trustLevel: 7,
        validForDays: 30,
      },
      issuerKeys
    );

    expect(credential.issuer).toBe(issuerId);
    expect(credential.credentialSubject.id).toBe(agentId);

    // Verify the credential
    const hybridKeys = issuerKeys as HybridKeyPair;
    const result = await ap.verifyCredential(credential, {
      pqcPublicKey: hybridKeys.pqc.publicKey,
      classicalPublicKey: hybridKeys.classical.publicKey,
    });

    expect(result.valid).toBe(true);
  });

  it('should check capabilities', async () => {
    const issuerKeys = (await new AstraCipherCrypto().generateIdentityKeys()) as HybridKeyPair;
    const credential = await ap.issueCredential(
      {
        issuerDID: 'did:astracipher:testnet:issuer',
        agentDID: 'did:astracipher:testnet:agent',
        name: 'CapAgent',
        capabilities: ['file.read', 'file.write', 'network.access'],
        permissions: [],
      },
      issuerKeys
    );

    expect(ap.hasCapability(credential, 'file.read')).toBe(true);
    expect(ap.hasCapability(credential, 'file.delete')).toBe(false);
  });

  it('should check permissions', async () => {
    const issuerKeys = (await new AstraCipherCrypto().generateIdentityKeys()) as HybridKeyPair;
    const credential = await ap.issueCredential(
      {
        issuerDID: 'did:astracipher:testnet:issuer',
        agentDID: 'did:astracipher:testnet:agent',
        name: 'PermAgent',
        capabilities: ['database'],
        permissions: [
          { resource: 'db:users', actions: ['read'] },
          { resource: 'db:products', actions: ['read', 'write'] },
        ],
      },
      issuerKeys
    );

    expect(ap.hasPermission(credential, 'db:users', 'read')).toBe(true);
    expect(ap.hasPermission(credential, 'db:users', 'write')).toBe(false);
    expect(ap.hasPermission(credential, 'db:products', 'write')).toBe(true);
  });

  it('should create and verify trust chains', async () => {
    const { didId: creatorId, keys: creatorKeys } = await ap.createAgent({ name: 'Creator' });

    const root = await ap.createTrustRoot(creatorId, creatorKeys);
    expect(root.did).toBe(creatorId);
    expect(root.depth).toBe(0);

    // Delegate to agent
    const { didId: agentId } = await ap.createAgent({ name: 'Agent' });
    const credential = await ap.issueCredential(
      {
        issuerDID: creatorId,
        agentDID: agentId,
        name: 'DelegatedAgent',
        capabilities: ['read'],
        permissions: [],
        trustLevel: 5,
        validForDays: 30,
      },
      creatorKeys
    );

    const agentLink = await ap.delegateTrust(root, agentId, credential, creatorKeys);
    expect(agentLink.depth).toBe(1);

    // Verify the chain
    const hybridCreatorKeys = creatorKeys as HybridKeyPair;
    const verification = await ap.verifyTrustChain([root, agentLink], async (did) => {
      if (did === creatorId) {
        return {
          pqcPublicKey: hybridCreatorKeys.pqc.publicKey,
          classicalPublicKey: hybridCreatorKeys.classical.publicKey,
        };
      }
      return null;
    });

    expect(verification.valid).toBe(true);
    expect(verification.depth).toBe(1);
  });
});
