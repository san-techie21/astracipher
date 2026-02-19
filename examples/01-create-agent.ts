/**
 * Example 1: Create an AI Agent Identity
 *
 * This example generates a post-quantum cryptographic identity for an AI agent
 * using ML-DSA-65 (FIPS 204) + ECDSA P-256 hybrid signing.
 *
 * Run: npx tsx examples/01-create-agent.ts
 */
import { AstraCipher } from '@astracipher/core';

async function main() {
  // Initialize AstraCipher in testnet mode (no registry server needed)
  const ap = new AstraCipher({ network: 'testnet' });

  console.log('AstraCipher SDK v' + ap.getVersion().sdk);
  console.log('Crypto: ' + ap.getVersion().crypto);
  console.log('');

  // Create an agent identity with hybrid post-quantum keys
  console.log('Generating post-quantum agent identity...');
  const t0 = performance.now();

  const { did, keys, didId } = await ap.createAgent({
    name: 'trading-agent-001',
    description: 'Automated equity trading agent',
    services: [
      {
        id: '#api',
        type: 'AgentService',
        serviceEndpoint: 'https://agents.example.com/trading-001',
        description: 'Agent API endpoint',
      },
    ],
  });

  const elapsed = (performance.now() - t0).toFixed(0);
  console.log(`Agent identity created in ${elapsed}ms\n`);

  // Display the DID
  console.log('DID:', didId);
  console.log('');

  // Display key information
  console.log('Verification Methods:');
  for (const vm of did.verificationMethod) {
    console.log(`  ${vm.type}: ${vm.publicKeyMultibase.slice(0, 32)}...`);
  }
  console.log('');

  // Verify the DID document is self-consistent
  const valid = await ap.verifyDID(did);
  console.log('DID self-verification:', valid ? 'PASSED' : 'FAILED');

  // The DID document is a standard W3C DID Document
  console.log('\nFull DID Document:');
  console.log(JSON.stringify(did, null, 2));
}

main().catch(console.error);
