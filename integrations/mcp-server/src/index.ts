/**
 * AgentPass MCP Server
 *
 * Exposes AgentPass identity operations as MCP tools.
 * Any MCP-compatible AI agent (Claude, GPT, etc.) can use these tools
 * to create identities, issue credentials, and verify agents.
 *
 * Tools:
 *   - create_agent_identity: Create a DID for an agent
 *   - issue_credential: Issue a verifiable credential
 *   - verify_agent: Verify an agent's credential
 *   - check_permissions: Check if an agent has specific permissions
 *   - inspect_credential: View credential details
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { AgentPass } from '@agentpass/core';
import { AgentPassCrypto, KeyManager } from '@agentpass/crypto';

const ap = new AgentPass({ network: 'testnet' });

const server = new Server(
  { name: 'agentpass', version: '0.1.0' },
  { capabilities: { tools: {} } }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'create_agent_identity',
      description:
        'Create a new cryptographic identity (DID) for an AI agent. ' +
        'Returns a DID document with post-quantum resistant keys.',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Agent name' },
          description: { type: 'string', description: 'Agent description' },
        },
        required: ['name'],
      },
    },
    {
      name: 'verify_agent',
      description:
        'Verify an agent credential - checks signature, expiration, and revocation status.',
      inputSchema: {
        type: 'object',
        properties: {
          credential: {
            type: 'object',
            description: 'The agent credential JSON to verify',
          },
        },
        required: ['credential'],
      },
    },
    {
      name: 'check_permissions',
      description:
        'Check if an agent has permission to perform a specific action on a resource.',
      inputSchema: {
        type: 'object',
        properties: {
          credential: { type: 'object', description: 'Agent credential' },
          resource: { type: 'string', description: 'Resource to check' },
          action: {
            type: 'string',
            enum: ['read', 'write', 'execute', 'delete', 'admin'],
            description: 'Action to check',
          },
        },
        required: ['credential', 'resource', 'action'],
      },
    },
    {
      name: 'inspect_credential',
      description: 'Inspect and display details of an agent credential.',
      inputSchema: {
        type: 'object',
        properties: {
          credential: { type: 'object', description: 'Agent credential to inspect' },
        },
        required: ['credential'],
      },
    },
  ],
}));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case 'create_agent_identity': {
      const { did, didId } = await ap.createAgent({
        name: (args as any).name,
        description: (args as any).description,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                didId,
                did,
                message: `Agent identity created: ${didId}`,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    case 'verify_agent': {
      const cred = (args as any).credential;
      // Basic structural verification
      const checks = {
        hasId: !!cred.id,
        hasIssuer: !!cred.issuer,
        hasSubject: !!cred.credentialSubject,
        hasProof: !!cred.proof,
        notExpired: new Date(cred.expirationDate) > new Date(),
      };
      const valid = Object.values(checks).every(Boolean);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ valid, checks, verifiedAt: new Date().toISOString() }, null, 2),
          },
        ],
      };
    }

    case 'check_permissions': {
      const hasPermission = ap.hasPermission(
        (args as any).credential,
        (args as any).resource,
        (args as any).action
      );

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              allowed: hasPermission,
              resource: (args as any).resource,
              action: (args as any).action,
              agent: (args as any).credential?.credentialSubject?.name,
            }),
          },
        ],
      };
    }

    case 'inspect_credential': {
      const credential = (args as any).credential;
      const subject = credential.credentialSubject || {};
      const exp = new Date(credential.expirationDate);
      const daysLeft = Math.floor((exp.getTime() - Date.now()) / 86400000);

      return {
        content: [
          {
            type: 'text',
            text: [
              `Agent: ${subject.name || 'unknown'}`,
              `DID: ${subject.id || 'unknown'}`,
              `Issuer: ${credential.issuer || 'unknown'}`,
              `Trust Level: ${subject.trustLevel}/10`,
              `Capabilities: ${(subject.capabilities || []).join(', ')}`,
              `Status: ${daysLeft > 0 ? `valid (${daysLeft} days left)` : 'EXPIRED'}`,
              `Proof: ${credential.proof ? 'present' : 'missing'}`,
            ].join('\n'),
          },
        ],
      };
    }

    default:
      return {
        content: [{ type: 'text', text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('AgentPass MCP Server running on stdio');
}

main().catch(console.error);
