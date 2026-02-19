/**
 * Example 3: Trust Chain Delegation
 *
 * This example builds a trust chain: Creator → Authorizer → Agent → Sub-agent
 * Each level has decreasing permissions (monotonic capability reduction).
 *
 * Run: npx tsx examples/03-trust-chain.ts
 */
import { AstraCipher } from '@astracipher/core';

async function main() {
  const ap = new AstraCipher({ network: 'testnet' });

  // Level 0: Trust Root (the organization)
  console.log('=== Building Trust Chain ===\n');

  console.log('Creating trust root (organization)...');
  const org = await ap.createAgent({ name: 'acme-corp' });
  const trustRoot = await ap.createTrustRoot(org.didId, org.keys);
  console.log(`Root: ${org.didId}`);
  console.log(`Role: ${trustRoot.role}, Depth: ${trustRoot.depth}\n`);

  // Level 1: Authorizer (a team lead or platform)
  console.log('Creating authorizer...');
  const authorizer = await ap.createAgent({ name: 'trading-platform' });
  const authorizerCred = await ap.issueCredential(
    {
      issuerDID: org.didId,
      agentDID: authorizer.didId,
      name: 'Platform Authorization',
      capabilities: ['market-data:read', 'orders:execute', 'portfolio:read', 'agents:manage'],
      permissions: [
        { resource: 'equity/*', actions: ['read', 'execute'] },
        { resource: 'agents/*', actions: ['read', 'create', 'manage'] },
      ],
      trustLevel: 9,
      validForDays: 365,
    },
    org.keys,
  );

  const authorizerLink = await ap.delegateTrust(
    trustRoot,
    authorizer.didId,
    authorizerCred,
    org.keys,
    'authorizer',
  );
  console.log(`Authorizer: ${authorizer.didId}`);
  console.log(`Role: ${authorizerLink.role}, Depth: ${authorizerLink.depth}\n`);

  // Level 2: Agent (a specific trading bot)
  console.log('Creating agent...');
  const agent = await ap.createAgent({ name: 'equity-trader-001' });
  const agentCred = await ap.issueCredential(
    {
      issuerDID: authorizer.didId,
      agentDID: agent.didId,
      name: 'Trading Bot Authorization',
      capabilities: ['market-data:read', 'orders:execute'],
      permissions: [
        { resource: 'equity/NSE/*', actions: ['read', 'execute'] },
      ],
      trustLevel: 7,
      validForDays: 90,
    },
    authorizer.keys,
  );

  const agentLink = await ap.delegateTrust(
    authorizerLink,
    agent.didId,
    agentCred,
    authorizer.keys,
    'agent',
  );
  console.log(`Agent: ${agent.didId}`);
  console.log(`Role: ${agentLink.role}, Depth: ${agentLink.depth}\n`);

  // Level 3: Sub-agent (a read-only monitor spawned by the agent)
  console.log('Creating sub-agent...');
  const subAgent = await ap.createAgent({ name: 'market-monitor' });
  const subAgentCred = await ap.issueCredential(
    {
      issuerDID: agent.didId,
      agentDID: subAgent.didId,
      name: 'Market Monitor',
      capabilities: ['market-data:read'],
      permissions: [
        { resource: 'equity/NSE/*', actions: ['read'] },
      ],
      trustLevel: 5,
      validForDays: 30,
    },
    agent.keys,
  );

  const subAgentLink = await ap.delegateTrust(
    agentLink,
    subAgent.didId,
    subAgentCred,
    agent.keys,
    'sub-agent',
  );
  console.log(`Sub-agent: ${subAgent.didId}`);
  console.log(`Role: ${subAgentLink.role}, Depth: ${subAgentLink.depth}\n`);

  // Verify the full chain
  console.log('=== Verifying Trust Chain ===\n');
  const chain = [trustRoot, authorizerLink, agentLink, subAgentLink];

  // Build a public key resolver (in production, this queries a registry)
  const keyStore = new Map<string, any>();
  keyStore.set(org.didId, org.keys);
  keyStore.set(authorizer.didId, authorizer.keys);
  keyStore.set(agent.didId, agent.keys);
  keyStore.set(subAgent.didId, subAgent.keys);

  const verification = await ap.verifyTrustChain(chain, async (did) => {
    const keys = keyStore.get(did);
    if (!keys) return null;
    // Return public keys in the format the verifier expects
    return 'pqc' in keys
      ? { pqcPublicKey: keys.pqc.publicKey, classicalPublicKey: keys.classical.publicKey }
      : { pqcPublicKey: keys.publicKey };
  });

  console.log('Chain valid:', verification.valid);
  console.log('Chain length:', verification.chainLength);
  console.log('Max depth reached:', verification.maxDepthReached);
  if (verification.errors.length > 0) {
    console.log('Errors:', verification.errors);
  }

  // Show effective permissions at the end of the chain
  console.log('\nEffective capabilities at sub-agent level:');
  const effective = ap.getVersion; // The chain intersection reduces permissions
  for (const link of chain) {
    if (link.credential) {
      console.log(`  ${link.role}: [${link.credential.credentialSubject.capabilities.join(', ')}]`);
    }
  }

  console.log('\nTrust chain demonstrates:');
  console.log('  1. Monotonic capability reduction (each level has fewer permissions)');
  console.log('  2. Cryptographic authorization at each delegation step');
  console.log('  3. Offline verification without contacting any server');
}

main().catch(console.error);
