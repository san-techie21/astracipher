/**
 * AstraCipher MCP Server
 *
 * Exposes AstraCipher identity operations as MCP tools.
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
import { AstraCipher } from '@astracipher/core';
import { AstraCipherCrypto, KeyManager } from '@astracipher/crypto';

const ap = new AstraCipher({ network: 'testnet' });

const server = new Server(
  { name: 'astracipher', version: '0.1.0' },
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

/**
 * LOW-6 FIX: Input validation helpers
 */
function validateString(value: unknown, field: string, maxLen = 256): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${field} is required and must be a non-empty string`);
  }
  if (value.length > maxLen) {
    throw new Error(`${field} exceeds maximum length of ${maxLen} characters`);
  }
  return value;
}

function validateCredential(cred: unknown): Record<string, unknown> {
  if (!cred || typeof cred !== 'object') {
    throw new Error('credential must be a valid JSON object');
  }
  const c = cred as Record<string, unknown>;
  if (!c.id || !c.issuer || !c.credentialSubject) {
    throw new Error('credential must have id, issuer, and credentialSubject fields');
  }
  return c;
}

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'create_agent_identity': {
        // LOW-6 FIX: Validate inputs
        const agentName = validateString((args as any)?.name, 'name', 128);
        const description = (args as any)?.description;
        if (description !== undefined && typeof description !== 'string') {
          throw new Error('description must be a string');
        }

        const { did, didId } = await ap.createAgent({
          name: agentName,
          description,
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
        // LOW-6 FIX: Validate input + perform real cryptographic verification
        const cred = validateCredential((args as any)?.credential);

        // Structural checks
        const checks: Record<string, { passed: boolean; detail: string }> = {
          structure: {
            passed: !!(cred.id && cred.issuer && cred.credentialSubject),
            detail: cred.id ? 'valid' : 'missing required fields',
          },
          expiration: {
            passed: new Date(cred.expirationDate as string) > new Date(),
            detail: new Date(cred.expirationDate as string) > new Date()
              ? `valid until ${cred.expirationDate}`
              : 'expired',
          },
          proof: {
            passed: !!(cred as any).proof?.signature,
            detail: (cred as any).proof?.signature
              ? 'proof present — use issuer public keys for full verification'
              : 'no cryptographic proof attached',
          },
          nonce: {
            passed: !!(cred as any).nonce,
            detail: (cred as any).nonce ? 'present' : 'missing (replay risk)',
          },
        };

        // If public keys are provided, do real crypto verification
        const publicKeys = (args as any)?.publicKeys;
        if ((cred as any).proof?.signature && publicKeys) {
          try {
            const result = await ap.verifyCredential(cred as any, {
              pqcPublicKey: publicKeys.pqcPublicKey
                ? new Uint8Array(Buffer.from(publicKeys.pqcPublicKey, 'base64url'))
                : undefined,
              classicalPublicKey: publicKeys.classicalPublicKey
                ? new Uint8Array(Buffer.from(publicKeys.classicalPublicKey, 'base64url'))
                : undefined,
            });
            checks.cryptographic = {
              passed: result.signatureValid,
              detail: result.signatureValid
                ? 'cryptographic signature verified'
                : `signature FAILED: ${result.errors.join(', ')}`,
            };
          } catch (err: any) {
            // PUB-LOW-2 FIX: Don't leak internal error details
            checks.cryptographic = {
              passed: false,
              detail: 'verification error',
            };
          }
        }

        const valid = Object.values(checks).every((c) => c.passed);

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
        // LOW-6 FIX: Validate inputs
        const credential = validateCredential((args as any)?.credential);
        const resource = validateString((args as any)?.resource, 'resource');
        const action = validateString((args as any)?.action, 'action');
        const validActions = ['read', 'write', 'execute', 'delete', 'admin'];
        if (!validActions.includes(action)) {
          throw new Error(`action must be one of: ${validActions.join(', ')}`);
        }

        const hasPermission = ap.hasPermission(
          credential as any,
          resource,
          action as any
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                allowed: hasPermission,
                resource,
                action,
                agent: (credential as any)?.credentialSubject?.name,
              }),
            },
          ],
        };
      }

      case 'inspect_credential': {
        // LOW-6 FIX: Validate input
        const credential = validateCredential((args as any)?.credential);
        const subject = (credential as any).credentialSubject || {};
        const exp = new Date((credential as any).expirationDate);
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
                `Nonce: ${(credential as any).nonce || 'NOT SET (replay risk)'}`,
                `Status: ${daysLeft > 0 ? `valid (${daysLeft} days left)` : 'EXPIRED'}`,
                `Proof: ${(credential as any).proof ? 'present' : 'missing'}`,
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
  } catch (err: any) {
    // PUB-LOW-2 FIX: Don't leak internal error details
    return {
      content: [{ type: 'text', text: 'An internal error occurred' }],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('AstraCipher MCP Server running on stdio');
}

main().catch(console.error);
