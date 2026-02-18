/**
 * Standalone A2A Adapter Server
 *
 * Run with: npx tsx src/server.ts
 *
 * Environment variables:
 *   AGENTPASS_URL          - AgentPass server URL (default: http://localhost:3456)
 *   AGENTPASS_API_KEY      - API key for AgentPass server
 *   A2A_PORT               - Port for A2A adapter (default: 3457)
 *   A2A_PUBLIC_URL         - Public URL where this adapter is reachable
 *   AGENT_DID              - DID of the agent to expose via A2A
 *   AGENT_NAME             - Human-readable agent name
 *   AGENT_DESCRIPTION      - Agent description
 */

import { A2AServer } from './a2a-server.js';
import type { TaskHandler, TaskState, Message } from './types.js';
import { v4 as uuidv4 } from 'uuid';

const AGENTPASS_URL = process.env.AGENTPASS_URL ?? 'http://localhost:3456';
// PUB-MED-8 FIX: Warn loudly when API key is missing
const API_KEY = process.env.AGENTPASS_API_KEY ?? '';
if (!API_KEY) {
  console.warn('\n\u26a0\ufe0f  WARNING: AGENTPASS_API_KEY is not set. Server will run without AgentPass authentication.');
  console.warn('   Set AGENTPASS_API_KEY environment variable for production use.\n');
}
const PORT = parseInt(process.env.A2A_PORT ?? '3457');
const PUBLIC_URL = process.env.A2A_PUBLIC_URL ?? `http://localhost:${PORT}`;
const AGENT_DID = process.env.AGENT_DID ?? 'did:agentpass:testnet:a2a-demo';
const AGENT_NAME = process.env.AGENT_NAME ?? 'AgentPass A2A Demo Agent';
const AGENT_DESCRIPTION =
  process.env.AGENT_DESCRIPTION ??
  'A demo A2A agent powered by AgentPass cryptographic identity. ' +
  'Supports post-quantum authentication and verifiable credentials.';

/**
 * Demo task handler — replace with real agent logic
 */
const demoHandler: TaskHandler = async (task, message, context) => {
  const inputText = message.parts
    .filter((p): p is { type: 'text'; text: string } => p.type === 'text')
    .map((p) => p.text)
    .join('\n');

  // Emit a status update while "working"
  context.updateStatus('working', 'Processing your request...');

  // Simulate some processing
  await new Promise((resolve) => setTimeout(resolve, 500));

  // Build response
  const responseLines = [
    `Hello! I'm ${AGENT_NAME}, an AgentPass-identified agent.`,
    '',
    `**Your message:** ${inputText.slice(0, 500)}`,
    '',
    '**Identity info:**',
    `- My DID: \`${AGENT_DID}\``,
    `- Your DID: \`${context.requesterDID ?? 'anonymous (no credential presented)'}\``,
    `- Authentication: ${context.requesterDID ? 'Verified via AgentPass' : 'None'}`,
    '',
    '**My capabilities:**',
    '- echo: Echo messages back',
    '- identify: Show identity information',
    '- health: Check health status',
    '',
    'This is a demo agent. Configure a custom `taskHandler` for real functionality.',
  ];

  // Emit an artifact
  context.emitArtifact({
    id: uuidv4(),
    name: 'response-metadata',
    parts: [
      {
        type: 'data',
        data: {
          agentDID: AGENT_DID,
          requesterDID: context.requesterDID ?? null,
          verified: !!context.requesterDID,
          timestamp: new Date().toISOString(),
          protocol: 'a2a-v0.3',
          identity: 'agentpass',
        },
      },
    ],
  });

  return {
    status: 'completed' as TaskState,
    messages: [
      {
        id: uuidv4(),
        role: 'agent' as const,
        parts: [{ type: 'text' as const, text: responseLines.join('\n') }],
      },
    ],
  };
};

// Create and start the server
const server = new A2AServer({
  agentpassUrl: AGENTPASS_URL,
  apiKey: API_KEY,
  port: PORT,
  publicUrl: PUBLIC_URL,
  network: 'testnet',
  enableStreaming: true,
  enablePushNotifications: false,
  taskHandler: demoHandler,
  agentCard: {
    did: AGENT_DID,
    name: AGENT_NAME,
    description: AGENT_DESCRIPTION,
    url: PUBLIC_URL,
    provider: {
      name: 'AgentPass Protocol',
      url: 'https://agentpass.dev',
      contactEmail: 'hello@agentpass.dev',
    },
    capabilities: {
      streaming: true,
      pushNotifications: false,
    },
    skills: [
      {
        id: 'echo',
        name: 'Echo',
        description: 'Echo back the received message with identity context',
        tags: ['demo', 'identity'],
      },
      {
        id: 'identify',
        name: 'Identify',
        description: 'Return the agent identity information and verify the caller',
        tags: ['identity', 'verification'],
      },
      {
        id: 'verify-credential',
        name: 'Verify Credential',
        description: 'Verify an AgentPass credential and return validation results',
        inputParameters: {
          type: 'object',
          properties: {
            credential: {
              type: 'object',
              description: 'The AgentPass credential to verify',
            },
          },
          required: ['credential'],
        },
        tags: ['identity', 'verification', 'security'],
      },
    ],
    trustLevel: 8,
    pqcAlgorithm: 'ML-DSA-65',
    compliance: [],
    documentationUrl: 'https://agentpass.dev/docs/a2a',
  },
});

server.start().catch((err) => {
  console.error('Failed to start A2A adapter:', err);
  process.exit(1);
});
