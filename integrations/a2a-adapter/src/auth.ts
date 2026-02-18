/**
 * A2A Authentication Bridge
 *
 * Bridges A2A protocol authentication with AstraCipher cryptographic identity.
 * Incoming A2A requests are authenticated against AstraCipher credentials,
 * enabling any A2A client to verify an agent's identity and trust level.
 *
 * Authentication flow:
 * 1. Client presents Bearer token (AstraCipher credential) or API key
 * 2. Adapter verifies credential against AstraCipher server
 * 3. Extracts agent DID, capabilities, and trust level
 * 4. Attaches identity context to the request
 *
 * This is the critical trust bridge — A2A protocol meets AstraCipher identity.
 */

import { timingSafeEqual as nodeTimingSafeEqual } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

export interface AuthenticatedRequest extends Request {
  astracipher?: {
    did: string;
    credentialId?: string;
    trustLevel?: number;
    capabilities?: string[];
    permissions?: Array<{ resource: string; actions: string[] }>;
    verified: boolean;
  };
}

export interface AuthConfig {
  /** AstraCipher server URL for credential verification */
  astracipherUrl: string;
  /** API key for communicating with AstraCipher server */
  apiKey?: string;
  /** List of valid API keys that clients can present (HIGH-5 FIX) */
  validApiKeys?: string[];
  /** Allow unauthenticated requests (for public agent cards) */
  allowUnauthenticated?: boolean;
  /** Skip verification for specific paths */
  publicPaths?: string[];
  /** Maximum Bearer token size in bytes (MED-7 FIX: prevents DoS via huge JSON.parse) */
  maxTokenSize?: number;
}

/**
 * Create Express middleware that authenticates A2A requests
 * using AstraCipher credentials
 */
export function createAuthMiddleware(config: AuthConfig) {
  const publicPaths = new Set(config.publicPaths ?? [
    '/.well-known/agent-card.json',
    '/health',
  ]);

  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    // Public paths don't need auth
    if (publicPaths.has(req.path)) {
      return next();
    }

    // Extract auth from headers
    const authHeader = req.headers.authorization;
    const apiKeyHeader = req.headers['x-astracipher-key'] as string | undefined;
    const didHeader = req.headers['x-astracipher-did'] as string | undefined;

    // Strategy 1: Bearer token (AstraCipher credential JWT)
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);

      // MED-7 FIX: Size limit on Bearer token before JSON.parse
      const maxSize = config.maxTokenSize ?? 64 * 1024; // 64 KB default
      if (Buffer.byteLength(token, 'utf-8') > maxSize) {
        return res.status(413).json({
          jsonrpc: '2.0',
          error: { code: -32013, message: 'Bearer token exceeds maximum size' },
          id: null,
        });
      }

      try {
        const identity = await verifyCredentialToken(token, config);
        req.astracipher = identity;
        return next();
      } catch (err: any) {
        // PUB-LOW-1 FIX: Don't leak credential parsing error details in logs
        console.warn('Credential verification failed (falling through to other strategies)');
      }
    }

    // Strategy 2: API key + DID header
    if (apiKeyHeader && didHeader) {
      try {
        const identity = await verifyApiKeyAndDID(apiKeyHeader, didHeader, config);
        req.astracipher = identity;
        return next();
      } catch (err: any) {
        // PUB-LOW-1 FIX: Don't leak verification error details in logs
        console.warn('API key + DID verification failed');
      }
    }

    // Strategy 3: API key only (server-level auth, no agent identity)
    // HIGH-5 FIX: Actually validate the API key against configured valid keys
    if (apiKeyHeader) {
      const validKeys = config.validApiKeys ?? [];
      if (validKeys.length > 0) {
        const isValid = validKeys.some((key) => timingSafeCompare(key, apiKeyHeader));
        if (!isValid) {
          return res.status(401).json({
            jsonrpc: '2.0',
            error: { code: -32010, message: 'Invalid API key' },
            id: null,
          });
        }
        req.astracipher = {
          did: 'api-key-user',
          verified: true,
        };
        return next();
      }
      // PUB-MED-3 FIX: When no validApiKeys are configured, warn and reject
      // instead of silently allowing any key through
      console.warn('WARNING: No validApiKeys configured — API key authentication is disabled. Set validApiKeys in AuthConfig to enable.');
      return res.status(503).json({
        jsonrpc: '2.0',
        error: { code: -32014, message: 'API key authentication not configured on this server' },
        id: null,
      });
    }

    // No auth provided
    if (config.allowUnauthenticated) {
      req.astracipher = {
        did: 'anonymous',
        verified: false,
      };
      return next();
    }

    return res.status(401).json({
      jsonrpc: '2.0',
      error: {
        code: -32010,
        message: 'Authentication required. Provide an AstraCipher credential via Bearer token or API key via X-AstraCipher-Key header.',
      },
      id: null,
    });
  };
}

/**
 * Verify a credential token against the AstraCipher server
 */
async function verifyCredentialToken(
  token: string,
  config: AuthConfig
): Promise<AuthenticatedRequest['astracipher'] & {}> {
  let credential: Record<string, unknown>;

  // Token could be base64-encoded JSON credential
  try {
    credential = JSON.parse(Buffer.from(token, 'base64url').toString());
  } catch {
    // Or raw JSON
    try {
      credential = JSON.parse(token);
    } catch {
      throw new Error('Invalid credential format');
    }
  }

  // Verify with AstraCipher server
  const verifyUrl = `${config.astracipherUrl.replace(/\/$/, '')}/api/v1/credentials/verify`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (config.apiKey) {
    headers['X-AstraCipher-Key'] = config.apiKey;
  }

  const response = await fetch(verifyUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ credential }),
  });

  if (!response.ok) {
    throw new Error(`Credential verification failed: ${response.status}`);
  }

  const result = (await response.json()) as Record<string, unknown>;

  if (!result.valid) {
    throw new Error('Credential is invalid');
  }

  // Extract identity from credential
  const subject = (credential.credentialSubject as Record<string, unknown>) ?? {};

  return {
    did: (subject.id as string) ?? 'unknown',
    credentialId: credential.id as string,
    trustLevel: subject.trustLevel as number,
    capabilities: (subject.capabilities as string[]) ?? [],
    permissions: (subject.permissions as Array<{ resource: string; actions: string[] }>) ?? [],
    verified: true,
  };
}

/**
 * Verify an API key and resolve the agent DID
 */
async function verifyApiKeyAndDID(
  apiKey: string,
  did: string,
  config: AuthConfig
): Promise<AuthenticatedRequest['astracipher'] & {}> {
  // Resolve the DID to confirm it exists
  const resolveUrl = `${config.astracipherUrl.replace(/\/$/, '')}/api/v1/did/${encodeURIComponent(did)}`;
  const headers: Record<string, string> = {
    'X-AstraCipher-Key': apiKey,
  };

  const response = await fetch(resolveUrl, { method: 'GET', headers });

  if (response.status === 404) {
    throw new Error(`DID not found: ${did}`);
  }
  if (!response.ok) {
    throw new Error(`DID resolution failed: ${response.status}`);
  }

  return {
    did,
    verified: true,
  };
}

/**
 * Require a minimum trust level for an endpoint
 */
export function requireTrustLevel(minLevel: number) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.astracipher?.verified) {
      return res.status(401).json({
        jsonrpc: '2.0',
        error: { code: -32010, message: 'Authentication required' },
        id: null,
      });
    }

    if ((req.astracipher.trustLevel ?? 0) < minLevel) {
      return res.status(403).json({
        jsonrpc: '2.0',
        error: {
          code: -32012,
          message: `Insufficient trust level: requires ${minLevel}, agent has ${req.astracipher.trustLevel ?? 0}`,
        },
        id: null,
      });
    }

    next();
  };
}

/**
 * Require specific capabilities for an endpoint
 */
export function requireCapability(...capabilities: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.astracipher?.verified) {
      return res.status(401).json({
        jsonrpc: '2.0',
        error: { code: -32010, message: 'Authentication required' },
        id: null,
      });
    }

    const agentCapabilities = new Set(req.astracipher.capabilities ?? []);
    const missing = capabilities.filter((c) => !agentCapabilities.has(c));

    if (missing.length > 0) {
      return res.status(403).json({
        jsonrpc: '2.0',
        error: {
          code: -32012,
          message: `Missing required capabilities: ${missing.join(', ')}`,
        },
        id: null,
      });
    }

    next();
  };
}

/**
 * Constant-time string comparison to prevent timing attacks on API keys.
 * HIGH-5 FIX: Uses Node.js built-in crypto.timingSafeEqual for battle-tested implementation.
 */
function timingSafeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');

  // Avoid length-based timing leak: if lengths differ, compare a against itself
  // but still return false
  if (bufA.length !== bufB.length) {
    nodeTimingSafeEqual(bufA, bufA); // dummy comparison to normalize timing
    return false;
  }

  return nodeTimingSafeEqual(bufA, bufB);
}
