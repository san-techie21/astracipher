/**
 * AgentPass End-to-End Test (Open Source)
 *
 * Simulates a real company (Acme Finance) using AgentPass to:
 * 1. Create agent identities (DIDs + PQC keys)
 * 2. Issue verifiable credentials with capabilities
 * 3. Verify credentials
 * 4. Check permissions (capability-based access control)
 * 5. Build and verify trust chains (delegation)
 * 6. Run compliance engine (compliance-core framework)
 *
 * NOTE: Framework-specific modules (DPDP, SEBI, etc.) are in the
 * private agentpass-platform repo. This test exercises the core
 * compliance engine with an inline sample module.
 */

import { AgentPass } from '@agentpass/core';
import { AgentPassCrypto } from '@agentpass/crypto';
import { ComplianceEngine, BaseComplianceModule } from '@agentpass/compliance-core';

/**
 * Sample compliance module for E2E testing.
 * Real modules (DPDP, GDPR, SEBI, etc.) live in agentpass-platform.
 */
class SampleComplianceModule extends BaseComplianceModule {
  id = 'gdpr';
  name = 'Sample GDPR Module';
  version = '0.1.0';

  getRequiredFields() {
    return [
      { key: 'consentReference', label: 'Consent Reference', type: 'string', required: true, description: 'Consent tracking ID' },
      { key: 'purposeLimitation', label: 'Purpose Limitation', type: 'array', required: true, description: 'Permitted processing purposes' },
      { key: 'dataMinimization', label: 'Data Minimization', type: 'boolean', required: true, description: 'Whether data minimization is enforced' },
      { key: 'retentionPeriod', label: 'Retention Period', type: 'string', required: true, description: 'Data retention period' },
      { key: 'crossBorderTransfer', label: 'Cross-Border Transfer', type: 'boolean', required: true, description: 'Whether cross-border transfer occurs' },
      { key: 'dpoContact', label: 'DPO Contact', type: 'string', required: true, description: 'Data Protection Officer contact' },
    ];
  }

  buildPayload(data) {
    return {
      framework: 'gdpr',
      consentReference: data.consentReference,
      purposes: data.purposeLimitation,
      minimization: data.dataMinimization,
      retention: data.retentionPeriod,
      crossBorder: data.crossBorderTransfer,
      dpo: data.dpoContact,
    };
  }

  async buildReportSections(_auditData, _period) {
    return [
      { title: 'Consent Management', content: 'Consent references tracked.', status: 'compliant', evidence: ['Consent log'] },
      { title: 'Purpose Limitation', content: 'Purposes defined and enforced.', status: 'compliant', evidence: ['Purpose registry'] },
      { title: 'Data Minimization', content: 'Minimization controls active.', status: 'compliant', evidence: ['Agent config'] },
      { title: 'Retention Policy', content: 'Retention periods enforced.', status: 'compliant', evidence: ['Retention schedule'] },
      { title: 'Cross-Border Transfers', content: 'Transfer controls in place.', status: 'compliant', evidence: ['Transfer log'] },
      { title: 'Breach Notification', content: 'DPO contact registered.', status: 'compliant', evidence: ['DPO registry'] },
    ];
  }
}

const PASS = '\x1b[32m✅ PASS\x1b[0m';
const FAIL = '\x1b[31m❌ FAIL\x1b[0m';
let passed = 0;
let failed = 0;

function check(name, condition, detail = '') {
  if (condition) {
    console.log(`  ${PASS} ${name}`);
    passed++;
  } else {
    console.log(`  ${FAIL} ${name} ${detail}`);
    failed++;
  }
}

async function main() {
  console.log('\n═══════════════════════════════════════════════════════');
  console.log('  AgentPass Protocol — End-to-End Test Suite');
  console.log('  Scenario: Acme Finance deploying AI trading agents');
  console.log('═══════════════════════════════════════════════════════\n');

  // ─────────────────────────────────────────
  // 1. CRYPTO LAYER (Post-Quantum)
  // ─────────────────────────────────────────
  console.log('┌─ 1. POST-QUANTUM CRYPTOGRAPHY ─────────────────┐');

  const crypto = new AgentPassCrypto();

  // Generate hybrid keys (PQC + Classical)
  const hybridKeys = await crypto.generateIdentityKeys();
  check('Generate hybrid identity keys',
    hybridKeys && hybridKeys.pqc && hybridKeys.classical);

  check('PQC algorithm is ML-DSA-65 (FIPS 204)',
    hybridKeys.pqc.algorithm === 'ml-dsa-65',
    `got: ${hybridKeys.pqc.algorithm}`);

  check('Classical algorithm is ECDSA P-256',
    hybridKeys.classical.algorithm === 'ecdsa-p256',
    `got: ${hybridKeys.classical.algorithm}`);

  check('Has PQC public key',
    hybridKeys.pqc.publicKey instanceof Uint8Array && hybridKeys.pqc.publicKey.length > 0);

  check('Has classical public key',
    hybridKeys.classical.publicKey instanceof Uint8Array && hybridKeys.classical.publicKey.length > 0);

  // Sign data with hybrid keys
  const testMessage = 'Transaction: Buy 100 shares AAPL @ $175.50';
  const signature = await crypto.sign(testMessage, hybridKeys);
  check('Sign transaction with hybrid keys',
    signature && signature.mode === 'hybrid');

  check('Hybrid signature has both PQC and classical parts',
    !!signature.pqcSignature && !!signature.classicalSignature);

  // Verify signature
  const verifyResult = await crypto.verify(testMessage, signature, {
    pqcPublicKey: hybridKeys.pqc.publicKey,
    classicalPublicKey: hybridKeys.classical.publicKey,
  });
  check('Verify hybrid signature', verifyResult.valid);
  check('Both PQC and classical verified individually',
    verifyResult.pqcValid && verifyResult.classicalValid);

  // Tampered message must fail
  const tamperResult = await crypto.verify('Transaction: Buy 999 shares AAPL @ $1.00', signature, {
    pqcPublicKey: hybridKeys.pqc.publicKey,
    classicalPublicKey: hybridKeys.classical.publicKey,
  });
  check('Tampered transaction fails verification', !tamperResult.valid);

  // KEM (Key Encapsulation Mechanism)
  const kemKeys = await crypto.generateKEMKeys();
  check('Generate KEM keys (ML-KEM-768)',
    kemKeys && kemKeys.algorithm === 'ml-kem-768');

  const encapResult = await crypto.encapsulate(kemKeys.publicKey);
  check('Key encapsulation succeeds',
    typeof encapResult.ciphertext === 'string' && encapResult.sharedSecret instanceof Uint8Array);

  const decapResult = await crypto.decapsulate(encapResult.ciphertext, kemKeys.secretKey);
  check('Key decapsulation succeeds', decapResult.success);
  check('Shared secrets match (secure channel established)',
    decapResult.success &&
    Buffer.from(encapResult.sharedSecret).equals(Buffer.from(decapResult.sharedSecret)));

  console.log('└────────────────────────────────────────────────┘\n');

  // ─────────────────────────────────────────
  // 2. AGENT IDENTITY (DIDs)
  // ─────────────────────────────────────────
  console.log('┌─ 2. AGENT IDENTITY (W3C DIDs) ─────────────────┐');

  const ap = new AgentPass({ network: 'testnet' });

  // Acme Finance creates their main trading agent
  const tradingAgent = await ap.createAgent({
    name: 'AcmeTradingBot',
    description: 'Automated equity trading agent for Acme Finance',
  });
  check('Create trading agent identity', tradingAgent && tradingAgent.didId);
  check('DID format is W3C compliant',
    tradingAgent.didId.startsWith('did:agentpass:testnet:'),
    `got: ${tradingAgent.didId}`);
  check('Agent has hybrid verification methods',
    tradingAgent.did.verificationMethod && tradingAgent.did.verificationMethod.length >= 2);

  // Create a data analysis agent
  const dataAgent = await ap.createAgent({
    name: 'AcmeDataAnalyzer',
    description: 'Market data analysis agent',
  });
  check('Create data analysis agent', dataAgent && dataAgent.didId);
  check('Agent DIDs are globally unique', tradingAgent.didId !== dataAgent.didId);

  // Verify DID document structure (W3C DID Core)
  const didDoc = tradingAgent.did;
  check('DID document id matches', didDoc.id === tradingAgent.didId);
  check('DID document has W3C context',
    Array.isArray(didDoc['@context']) && didDoc['@context'].includes('https://www.w3.org/ns/did/v1'));
  check('DID document has verification methods', didDoc.verificationMethod.length > 0);

  console.log('└────────────────────────────────────────────────┘\n');

  // ─────────────────────────────────────────
  // 3. VERIFIABLE CREDENTIALS + PERMISSIONS
  // ─────────────────────────────────────────
  console.log('┌─ 3. VERIFIABLE CREDENTIALS & PERMISSIONS ───────┐');

  // Acme Finance issues a credential to the trading agent
  const tradingCredential = await ap.issueCredential(
    {
      issuerDID: tradingAgent.didId,  // Self-issued (company's root DID)
      agentDID: tradingAgent.didId,
      name: 'AcmeTradingBot',
      description: 'Full trading capabilities for Acme Finance',
      capabilities: ['market-data:read', 'equity:trade', 'reporting:generate'],
      permissions: [
        { resource: 'api/markets/*', actions: ['read'] },
        { resource: 'api/orders/*', actions: ['read', 'write'] },
        { resource: 'api/reports/*', actions: ['read', 'write'] },
      ],
      trustLevel: 8,
      validForDays: 90,
    },
    tradingAgent.keys
  );
  check('Issue trading credential', tradingCredential && tradingCredential.id);
  check('Credential type includes VerifiableCredential',
    tradingCredential.type.includes('VerifiableCredential'));
  check('Credential type includes AgentIdentityCredential',
    tradingCredential.type.includes('AgentIdentityCredential'));
  check('Credential has issuer DID',
    tradingCredential.issuer.startsWith('did:agentpass:'));
  check('Credential has 3 capabilities',
    tradingCredential.credentialSubject.capabilities.length === 3);
  check('Credential has 3 permission rules',
    tradingCredential.credentialSubject.permissions.length === 3);
  check('Trust level is 8',
    tradingCredential.credentialSubject.trustLevel === 8);
  check('Credential has expiration',
    !!tradingCredential.expirationDate);
  check('Credential has hybrid proof',
    tradingCredential.proof && tradingCredential.proof.type === 'AgentPassHybridSignature2026');

  // Verify the credential
  const credVerify = await ap.verifyCredential(tradingCredential, {
    pqcPublicKey: tradingAgent.keys.pqc.publicKey,
    classicalPublicKey: tradingAgent.keys.classical.publicKey,
  });
  check('Verify credential signature', credVerify.valid);

  // Permission checks (the core access control)
  check('Can read market data',
    ap.hasPermission(tradingCredential, 'api/markets/stocks', 'read'));
  check('Can write orders (create/update)',
    ap.hasPermission(tradingCredential, 'api/orders/new', 'write'));
  check('Can write reports',
    ap.hasPermission(tradingCredential, 'api/reports/quarterly', 'write'));
  check('CANNOT delete orders (not permitted)',
    !ap.hasPermission(tradingCredential, 'api/orders/123', 'delete'));
  check('CANNOT access admin (not in scope)',
    !ap.hasPermission(tradingCredential, 'admin/system', 'write'));

  // Capability checks
  check('Has market-data:read capability',
    ap.hasCapability(tradingCredential, 'market-data:read'));
  check('Has equity:trade capability',
    ap.hasCapability(tradingCredential, 'equity:trade'));
  check('Does NOT have admin:full capability',
    !ap.hasCapability(tradingCredential, 'admin:full'));

  // Issue a READ-ONLY credential for the data agent
  const readOnlyCredential = await ap.issueCredential(
    {
      issuerDID: tradingAgent.didId,
      agentDID: dataAgent.didId,
      name: 'AcmeDataAnalyzer',
      capabilities: ['data:read'],
      permissions: [
        { resource: 'api/reports/*', actions: ['read'] },
      ],
      trustLevel: 3,
      validForDays: 7,
    },
    tradingAgent.keys
  );
  check('Issue read-only credential', readOnlyCredential && readOnlyCredential.id);
  check('Read-only credential has lower trust level',
    readOnlyCredential.credentialSubject.trustLevel === 3);
  check('Read-only credential CANNOT trade',
    !ap.hasCapability(readOnlyCredential, 'equity:trade'));
  check('Read-only credential CANNOT write orders',
    !ap.hasPermission(readOnlyCredential, 'api/orders/new', 'write'));

  console.log('└────────────────────────────────────────────────┘\n');

  // ─────────────────────────────────────────
  // 4. TRUST CHAINS (Delegation of Authority)
  // ─────────────────────────────────────────
  console.log('┌─ 4. TRUST CHAINS (Delegation) ──────────────────┐');

  // Build key store for resolution
  const keyStore = {};
  keyStore[tradingAgent.didId] = {
    pqcPublicKey: tradingAgent.keys.pqc.publicKey,
    classicalPublicKey: tradingAgent.keys.classical.publicKey,
  };
  keyStore[dataAgent.didId] = {
    pqcPublicKey: dataAgent.keys.pqc.publicKey,
    classicalPublicKey: dataAgent.keys.classical.publicKey,
  };

  // Create trust chain root (Acme Finance is the root of trust)
  const root = await ap.createTrustRoot(tradingAgent.didId, tradingAgent.keys);
  check('Create trust chain root', !!root && root.role === 'creator');
  check('Root has depth 0', root.depth === 0);

  // Delegate trust to the data agent
  const delegatedLink = await ap.delegateTrust(
    root,
    dataAgent.didId,
    readOnlyCredential,
    tradingAgent.keys,
    'agent'
  );
  check('Delegate trust to data agent', !!delegatedLink);
  check('Delegation has depth 1', delegatedLink.depth === 1);

  // Verify the trust chain
  const chainVerification = await ap.verifyTrustChain(
    [root, delegatedLink],
    async (did) => keyStore[did] || null
  );
  check('Verify trust chain', chainVerification.valid,
    chainVerification.errors?.join(', '));
  check('Trust chain depth is 1', chainVerification.depth === 1);
  check('No trust chain errors',
    chainVerification.errors.length === 0,
    chainVerification.errors?.join(', '));

  console.log('└────────────────────────────────────────────────┘\n');

  // ─────────────────────────────────────────
  // 5. COMPLIANCE ENGINE (Core Framework)
  // ─────────────────────────────────────────
  console.log('┌─ 5. COMPLIANCE ENGINE (Core Framework) ─────────┐');

  const complianceEngine = new ComplianceEngine({
    organizationDID: tradingAgent.didId,
    frameworks: ['gdpr'],
    reportingPeriod: 'quarterly',
  });
  const sampleModule = new SampleComplianceModule();
  complianceEngine.registerModule(sampleModule);

  check('Compliance engine created', !!complianceEngine);
  check('GDPR framework active', complianceEngine.getActiveFrameworks().includes('gdpr'));

  // Acme Finance's compliant configuration
  const compliantConfig = {
    consentReference: 'CONSENT-001',
    purposeLimitation: ['analytics', 'trading'],
    dataMinimization: true,
    retentionPeriod: '365d',
    crossBorderTransfer: false,
    dpoContact: 'dpo@acmefinance.com',
  };

  // checkGaps expects data keyed by framework ID: { gdpr: { ... } }
  const gaps = complianceEngine.checkGaps({ gdpr: compliantConfig });
  check('Fully compliant config has no gaps', gaps.length === 0,
    gaps.length > 0 ? `gaps: ${gaps.map(g => g.field).join(', ')}` : '');

  // Non-compliant configuration (missing required fields)
  const nonCompliantConfig = {
    purposeLimitation: ['analytics'],
    dataMinimization: false,
    crossBorderTransfer: true,
  };

  const nonCompliantGaps = complianceEngine.checkGaps({ gdpr: nonCompliantConfig });
  check('Detects non-compliant config', nonCompliantGaps.length > 0,
    `found ${nonCompliantGaps.length} gaps`);

  const highOrCritGaps = nonCompliantGaps.filter(g => g.severity === 'critical' || g.severity === 'high');
  check('Identifies high/critical compliance gaps', highOrCritGaps.length > 0,
    `found ${highOrCritGaps.length} high/critical gaps`);

  // Generate compliance reports
  const now = new Date();
  const threeMonthsAgo = new Date(now.getTime() - 90 * 86400 * 1000);
  const reports = await complianceEngine.generateReports({
    period: { from: threeMonthsAgo.toISOString(), to: now.toISOString() },
    auditData: [],
  });
  check('Generate compliance reports', !!reports);

  const reportFrameworks = Object.keys(reports);
  check('Report covers registered frameworks', reportFrameworks.length > 0);

  const gdprReport = reports['gdpr'];
  check('Report has numeric score', typeof gdprReport.score === 'number');
  check('Report has sections', Array.isArray(gdprReport.sections) && gdprReport.sections.length > 0);
  check('Report has 6+ compliance sections',
    gdprReport.sections.length >= 6,
    `got ${gdprReport.sections.length} sections`);

  // Build compliance payload for credential enrichment
  const payload = complianceEngine.buildCompliancePayload({ gdpr: compliantConfig });
  check('Build compliance payload', !!payload && !!payload.gdpr);
  check('Payload has framework metadata',
    payload.gdpr && payload.gdpr.framework === 'gdpr');

  console.log('└────────────────────────────────────────────────┘\n');

  // ─────────────────────────────────────────
  // 6. REAL-WORLD SCENARIO SIMULATION
  // ─────────────────────────────────────────
  console.log('┌─ 6. REAL-WORLD SCENARIO ────────────────────────┐');

  // Scenario: Agent tries to execute a trade
  const tradeAction = ap.hasPermission(tradingCredential, 'api/orders/buy-aapl', 'write');
  check('Trading agent can place buy order', tradeAction);

  // Scenario: Agent tries to read market data
  const readMarket = ap.hasPermission(tradingCredential, 'api/markets/nasdaq/aapl', 'read');
  check('Trading agent can read AAPL market data', readMarket);

  // Scenario: Read-only agent tries to trade (should fail)
  const unauthorizedTrade = ap.hasPermission(readOnlyCredential, 'api/orders/buy-aapl', 'write');
  check('Read-only agent CANNOT place trade', !unauthorizedTrade);

  // Scenario: Verify credential hasn't been tampered
  const tamperedCred = JSON.parse(JSON.stringify(tradingCredential));
  tamperedCred.credentialSubject.trustLevel = 10; // Tamper: boost trust level
  const tamperedVerify = await ap.verifyCredential(tamperedCred, {
    pqcPublicKey: tradingAgent.keys.pqc.publicKey,
    classicalPublicKey: tradingAgent.keys.classical.publicKey,
  });
  check('Tampered credential fails verification', !tamperedVerify.valid);

  console.log('└────────────────────────────────────────────────┘\n');

  // ─────────────────────────────────────────
  // SUMMARY
  // ─────────────────────────────────────────
  console.log('═══════════════════════════════════════════════════════');
  console.log(`  RESULTS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  console.log('═══════════════════════════════════════════════════════\n');

  if (failed > 0) {
    console.log('⚠️  Some tests failed. See details above.\n');
    process.exit(1);
  } else {
    console.log('🎉 All E2E tests passed! AgentPass protocol is working correctly.\n');
    console.log('  The protocol successfully provides:');
    console.log('  • Post-quantum cryptographic identity (ML-DSA-65 + ECDSA P-256)');
    console.log('  • Secure key exchange (ML-KEM-768)');
    console.log('  • W3C DID-compliant agent identities');
    console.log('  • Verifiable credentials with capability-based access control');
    console.log('  • Trust chain delegation with signature verification');
    console.log('  • Pluggable compliance engine (GDPR, DPDP, SEBI modules)');
    console.log('  • Tamper detection on credentials\n');
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('\n💥 E2E test crashed:', err);
  process.exit(2);
});
