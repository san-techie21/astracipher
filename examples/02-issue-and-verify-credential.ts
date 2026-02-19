/**
 * Example 2: Issue and Verify a Credential
 *
 * This example creates an issuer, issues a verifiable credential to an agent,
 * and then verifies it — all offline, no server needed.
 *
 * Run: npx tsx examples/02-issue-and-verify-credential.ts
 */
import { AstraCipher } from '@astracipher/core';

async function main() {
  const ap = new AstraCipher({ network: 'testnet' });

  // Step 1: Create the issuer (e.g., a platform or organization)
  console.log('Creating issuer identity...');
  const issuer = await ap.createAgent({ name: 'acme-platform' });
  console.log('Issuer DID:', issuer.didId);

  // Step 2: Create the agent (e.g., a trading bot)
  console.log('\nCreating agent identity...');
  const agent = await ap.createAgent({
    name: 'trading-bot-alpha',
    description: 'High-frequency trading agent',
  });
  console.log('Agent DID:', agent.didId);

  // Step 3: Issue a credential from the issuer to the agent
  console.log('\nIssuing verifiable credential...');
  const credential = await ap.issueCredential(
    {
      issuerDID: issuer.didId,
      agentDID: agent.didId,
      name: 'Trading Agent Authorization',
      description: 'Authorized to execute trades on equity markets',
      capabilities: ['market-data:read', 'orders:execute', 'portfolio:read'],
      permissions: [
        { resource: 'equity/*', actions: ['read', 'execute'] },
        { resource: 'crypto/BTC', actions: ['read'] },
        { resource: 'admin/*', actions: [] }, // explicitly no admin access
      ],
      trustLevel: 7,
      validForDays: 90,
      rateLimits: {
        requestsPerMinute: 100,
        requestsPerHour: 5000,
      },
    },
    issuer.keys,
  );

  console.log('Credential ID:', credential.id);
  console.log('Signed with:', credential.proof?.type);
  console.log('Expires:', credential.expirationDate);

  // Step 4: Verify the credential (offline — pass issuer's public keys directly)
  console.log('\n--- Verification ---');
  const issuerPublicKeys = {
    pqcPublicKey: 'pqc' in issuer.keys ? issuer.keys.pqc.publicKey : undefined,
    classicalPublicKey: 'classical' in issuer.keys ? issuer.keys.classical.publicKey : undefined,
  };
  const result = await ap.verifyCredential(credential, issuerPublicKeys);

  console.log('Valid:', result.valid);
  console.log('Expired:', result.expired);
  console.log('Signature valid:', result.signatureValid);
  if (result.errors.length > 0) {
    console.log('Errors:', result.errors);
  }

  // Step 5: Check specific permissions
  console.log('\n--- Permission Checks ---');
  const checks = [
    ['equity/RELIANCE', 'read'],
    ['equity/RELIANCE', 'execute'],
    ['crypto/BTC', 'read'],
    ['crypto/BTC', 'execute'],
    ['admin/settings', 'read'],
  ] as const;

  for (const [resource, action] of checks) {
    const allowed = ap.hasPermission(credential, resource, action);
    console.log(`  ${resource} → ${action}: ${allowed ? '✓ ALLOWED' : '✗ DENIED'}`);
  }

  // Step 6: Check capabilities
  console.log('\n--- Capability Checks ---');
  for (const cap of ['market-data:read', 'orders:execute', 'admin:write']) {
    const has = ap.hasCapability(credential, cap);
    console.log(`  ${cap}: ${has ? '✓ YES' : '✗ NO'}`);
  }
}

main().catch(console.error);
