/**
 * Agent Card Builder
 *
 * Generates A2A-compliant Agent Cards from AgentPass identity data.
 * An Agent Card is the discovery document that tells other agents:
 *   - Who this agent is (DID, name, provider)
 *   - What it can do (skills, capabilities)
 *   - How to talk to it (endpoint, auth schemes)
 *   - Why to trust it (AgentPass PQC signature, trust level, compliance)
 *
 * The card is served at /.well-known/agent-card.json per RFC 8615.
 */

import type {
  AgentCard,
  AgentSkill,
  AgentCapabilities,
  SecurityScheme,
  AgentCardSignature,
  A2AAdapterConfig,
} from './types.js';
import { AgentPassCrypto } from '@agentpass/crypto';

export interface AgentCardOptions {
  /** Agent DID from AgentPass */
  did: string;
  /** Human-readable agent name */
  name: string;
  /** Agent description */
  description?: string;
  /** A2A endpoint URL */
  url: string;
  /** Agent skills / operations */
  skills: AgentSkill[];
  /** Provider organization info */
  provider?: {
    name: string;
    contactEmail?: string;
    url?: string;
  };
  /** Capabilities flags */
  capabilities?: AgentCapabilities;
  /** AgentPass trust level (1-10) */
  trustLevel?: number;
  /** Compliance frameworks satisfied */
  compliance?: string[];
  /** PQC algorithm used for identity keys */
  pqcAlgorithm?: string;
  /** AgentPass credential ID */
  credentialId?: string;
  /** Documentation URL */
  documentationUrl?: string;
  /** Additional security schemes beyond the default AgentPass scheme */
  additionalSecuritySchemes?: Record<string, SecurityScheme>;
}

/**
 * Build an A2A Agent Card from AgentPass identity data
 */
export function buildAgentCard(options: AgentCardOptions): AgentCard {
  const securitySchemes: Record<string, SecurityScheme> = {
    // AgentPass credential-based auth (primary)
    agentpass: {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'AgentPass-Credential',
      description:
        'AgentPass verifiable credential. Present a valid credential ' +
        'with the agent DID in the Authorization header as: Bearer <credential-jwt>',
    },
    // Standard API key auth (fallback)
    apiKey: {
      type: 'apiKey',
      name: 'X-AgentPass-Key',
      in: 'header',
      description: 'AgentPass API key for server-level authentication',
    },
    ...options.additionalSecuritySchemes,
  };

  const card: AgentCard = {
    id: options.did,
    name: options.name,
    description: options.description,
    url: options.url,
    version: '0.3',
    skills: options.skills,
    capabilities: {
      streaming: options.capabilities?.streaming ?? false,
      pushNotifications: options.capabilities?.pushNotifications ?? false,
      extendedAgentCard: true, // always available via /extendedAgentCard
    },
    interfaces: [
      { protocol: 'json-rpc', url: options.url },
      { protocol: 'http', url: options.url },
    ],
    defaultInputModes: ['application/json', 'text/plain'],
    defaultOutputModes: ['application/json', 'text/plain'],
    securitySchemes,
    security: [{ agentpass: [] }, { apiKey: [] }],

    // AgentPass extensions — the value-add
    'x-agentpass-did': options.did,
    'x-agentpass-pqc-algorithm': options.pqcAlgorithm ?? 'ML-DSA-65',
    'x-agentpass-trust-level': options.trustLevel,
    'x-agentpass-compliance': options.compliance,
  };

  if (options.credentialId) {
    card['x-agentpass-credential'] = options.credentialId;
  }

  if (options.provider) {
    card.provider = options.provider;
  }

  if (options.documentationUrl) {
    card.documentationUrl = options.documentationUrl;
  }

  return card;
}

/**
 * Build an Agent Card from an AgentPass server's DID document and credential
 */
export function buildAgentCardFromDID(
  didDocument: Record<string, unknown>,
  credential: Record<string, unknown> | null,
  config: A2AAdapterConfig & { skills: AgentSkill[] }
): AgentCard {
  const subject = (credential?.credentialSubject as Record<string, unknown>) ?? {};

  return buildAgentCard({
    did: didDocument.id as string,
    name: (subject.name as string) ?? (didDocument.id as string),
    description: (subject.description as string) ?? 'AgentPass-identified AI agent',
    url: config.publicUrl ?? `http://localhost:${config.port ?? 3457}`,
    skills: config.skills,
    provider: {
      name: 'AgentPass Protocol',
      url: 'https://agentpass.dev',
    },
    capabilities: {
      streaming: config.enableStreaming ?? false,
      pushNotifications: config.enablePushNotifications ?? false,
    },
    trustLevel: subject.trustLevel as number,
    compliance: (subject.compliance as string[]) ?? [],
    pqcAlgorithm: detectPQCAlgorithm(didDocument),
    credentialId: credential?.id as string,
  });
}

/**
 * Detect which PQC algorithm is used from the DID document's verification methods
 */
function detectPQCAlgorithm(didDocument: Record<string, unknown>): string {
  const methods = (didDocument.verificationMethod as any[]) ?? [];
  for (const method of methods) {
    if (method.type?.includes('ML-DSA')) return 'ML-DSA-65';
    if (method.type?.includes('SLH-DSA')) return 'SLH-DSA-SHA2-128f';
  }
  return 'ML-DSA-65';
}

/**
 * Sign an Agent Card using AgentPass crypto
 * Returns the card with an attached signature
 */
export async function signAgentCard(
  card: AgentCard,
  signFn: (data: Uint8Array) => Promise<{ signature: string; publicKey: string }>
): Promise<AgentCard> {
  // PUB-LOW-9 FIX: Use deep canonical JSON from @agentpass/crypto
  // (shallow Object.keys().sort() missed nested objects)
  const { signature: _sig, ...cardWithoutSig } = card;
  const canonical = AgentPassCrypto.canonicalJSON(cardWithoutSig);
  const data = new TextEncoder().encode(canonical);

  const result = await signFn(data);

  return {
    ...card,
    signature: {
      publicKey: result.publicKey,
      signature: result.signature,
      algorithm: 'hybrid-pqc', // AgentPass hybrid ML-DSA-65 + ECDSA
    },
  };
}

/**
 * Verify an Agent Card's signature
 */
export async function verifyAgentCardSignature(
  card: AgentCard,
  verifyFn: (data: Uint8Array, signature: string, publicKey: string) => Promise<boolean>
): Promise<boolean> {
  if (!card.signature) return false;

  const { signature, ...cardWithoutSig } = card;
  // PUB-LOW-9 FIX: Use deep canonical JSON (matches signAgentCard)
  const canonical = AgentPassCrypto.canonicalJSON(cardWithoutSig);
  const data = new TextEncoder().encode(canonical);

  return verifyFn(data, signature.signature, signature.publicKey);
}
