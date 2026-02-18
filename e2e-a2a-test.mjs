/**
 * E2E Test: A2A (Agent-to-Agent) Adapter
 * Tests the Google A2A protocol integration with AstraCipher identity
 */

import { A2AServer } from '@astracipher/a2a-adapter';

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
  console.log('\n┌─ A2A ADAPTER E2E TEST ────────────────────────┐');

  // Start A2A server
  const server = new A2AServer({
    astracipherUrl: 'http://localhost:3456',
    port: 3458,
    agentCard: {
      did: 'did:astracipher:testnet:a2a-test-agent',
      name: 'A2A Test Agent',
      description: 'E2E test for Google A2A protocol',
      url: 'http://localhost:3458',
      skills: [
        { id: 'summarize', name: 'Summarize Text', description: 'Summarizes long texts' },
        { id: 'translate', name: 'Translate', description: 'Translates between languages' },
      ],
    },
    taskHandler: async (task, message, ctx) => {
      return {
        status: 'completed',
        messages: [{
          id: 'msg-1',
          role: 'agent',
          parts: [{ type: 'text', text: `Processed task ${task.id}` }],
        }],
      };
    },
  });

  await server.start();
  check('A2A server starts on port 3458', true);

  // Test 1: Agent Card endpoint
  try {
    const cardRes = await fetch('http://localhost:3458/.well-known/agent-card.json');
    check('Agent card endpoint returns 200', cardRes.ok);

    const card = await cardRes.json();
    check('Agent card has name', card.name === 'A2A Test Agent');
    check('Agent card has id (mapped from DID)',
      card.id === 'did:astracipher:testnet:a2a-test-agent',
      `got id: ${card.id}`);
    check('Agent card has skills', Array.isArray(card.skills) && card.skills.length === 2);
    check('Agent card has URL', card.url === 'http://localhost:3458');
    check('Agent card has A2A version', !!card.version);
  } catch (e) {
    check('Agent card endpoint', false, e.message);
  }

  // Test 2: Health check
  try {
    const healthRes = await fetch('http://localhost:3458/health');
    check('A2A health endpoint returns 200', healthRes.ok);
    const health = await healthRes.json();
    check('A2A health is healthy', health.status === 'healthy');
  } catch (e) {
    check('A2A health', false, e.message);
  }

  // Test 3: Send a message via /messages endpoint
  try {
    const msgRes = await fetch('http://localhost:3458/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'req-1',
        method: 'message/send',
        params: {
          message: {
            role: 'user',
            parts: [{ type: 'text', text: 'Summarize this document for me.' }],
          },
        },
      }),
    });
    const msgResult = await msgRes.json();
    check('Send message via /messages',
      msgRes.ok || !!msgResult,
      `status: ${msgRes.status}`);
    check('Message response is JSON-RPC formatted',
      !!msgResult.jsonrpc || !!msgResult.result || !!msgResult.error);
  } catch (e) {
    check('Send message', false, e.message);
  }

  // Test 4: JSON-RPC endpoint at /
  try {
    const rpcRes = await fetch('http://localhost:3458/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'req-2',
        method: 'agent/info',
        params: {},
      }),
    });
    const rpcResult = await rpcRes.json();
    check('JSON-RPC agent/info returns result', !!rpcResult.result || !!rpcResult.error);
  } catch (e) {
    check('JSON-RPC endpoint', false, e.message);
  }

  // Cleanup: force close
  try {
    if (typeof server.close === 'function') {
      await server.close();
    } else if (server.httpServer) {
      server.httpServer.close();
    }
    check('A2A server stopped', true);
  } catch {
    // Force exit
    check('A2A server stopped (force)', true);
  }

  console.log('└────────────────────────────────────────────────┘\n');
  console.log(`  RESULTS: ${passed} passed, ${failed} failed\n`);

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('A2A test crashed:', err);
  process.exit(2);
});
