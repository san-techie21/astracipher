/**
 * @astracipher/a2a-adapter
 *
 * Google A2A (Agent-to-Agent) protocol adapter for AstraCipher.
 *
 * This package bridges the A2A protocol with AstraCipher's cryptographic
 * identity system, enabling:
 *
 * 1. Agent Discovery — Serve A2A Agent Cards enriched with AstraCipher DID,
 *    PQC algorithm info, trust levels, and compliance metadata
 *
 * 2. Authenticated Communication — A2A requests are authenticated using
 *    AstraCipher credentials (Bearer tokens) or API keys
 *
 * 3. Task Management — Full A2A task lifecycle (submit → work → complete)
 *    with AstraCipher identity context attached to every task
 *
 * 4. Client SDK — Discover and communicate with external A2A agents,
 *    presenting AstraCipher credentials for authentication
 *
 * Quick Start (Server):
 *
 *   import { A2AServer } from '@astracipher/a2a-adapter';
 *
 *   const server = new A2AServer({
 *     astracipherUrl: 'http://localhost:3456',
 *     port: 3457,
 *     agentCard: {
 *       did: 'did:astracipher:testnet:abc123',
 *       name: 'My Agent',
 *       url: 'http://localhost:3457',
 *       skills: [
 *         { id: 'summarize', name: 'Summarize', description: 'Summarize text' },
 *       ],
 *     },
 *     taskHandler: async (task, message, ctx) => {
 *       // Your agent logic here
 *       return { status: 'completed', messages: [...] };
 *     },
 *   });
 *
 *   await server.start();
 *
 * Quick Start (Client):
 *
 *   import { A2AClient } from '@astracipher/a2a-adapter';
 *
 *   const client = new A2AClient({
 *     credential: myCredential,
 *     agentDID: 'did:astracipher:testnet:myagent',
 *   });
 *
 *   const card = await client.discoverAgent('https://other-agent.example.com');
 *   const task = await client.sendMessage(card.url, 'Hello, agent!');
 *
 * @see https://a2a-protocol.org/latest/specification/
 * @see https://astracipher.com
 */

// Server
export { A2AServer, type A2AServerOptions } from './a2a-server.js';

// Client
export { A2AClient, A2ARemoteError, type A2AClientConfig } from './a2a-client.js';

// Agent Card
export {
  buildAgentCard,
  buildAgentCardFromDID,
  signAgentCard,
  verifyAgentCardSignature,
  type AgentCardOptions,
} from './agent-card.js';

// Task Manager
export {
  TaskManager,
  TaskNotFoundError,
  TaskNotCancelableError,
} from './task-manager.js';

// Auth
export {
  createAuthMiddleware,
  requireTrustLevel,
  requireCapability,
  type AuthenticatedRequest,
  type AuthConfig,
} from './auth.js';

// Types
export type {
  AgentCard,
  AgentProvider,
  AgentCapabilities,
  AgentSkill,
  AgentInterface,
  SecurityScheme,
  AgentCardSignature,
  Task,
  TaskState,
  TaskStatus,
  Message,
  Role,
  Part,
  TextPart,
  FilePart,
  DataPart,
  Artifact,
  TaskStatusUpdateEvent,
  TaskArtifactUpdateEvent,
  JsonRpcRequest,
  JsonRpcResponse,
  JsonRpcError,
  PushNotificationConfig,
  A2AAdapterConfig,
  TaskHandler,
  TaskHandlerContext,
  TaskHandlerResult,
} from './types.js';

export { A2A_ERRORS } from './types.js';
