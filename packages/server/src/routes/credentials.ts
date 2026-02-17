/**
 * Credential Verification & Revocation API Routes
 */

import { Router } from 'express';
import { z } from 'zod';

const router = Router();

// In-memory stores (replace with PostgreSQL)
const credentialStore = new Map<string, any>();
const revocationSet = new Set<string>();

/**
 * POST /api/v1/credentials - Register a credential
 */
router.post('/', async (req, res) => {
  try {
    const credential = req.body;

    if (!credential.id || !credential.issuer || !credential.credentialSubject) {
      return res.status(400).json({ error: 'Invalid credential structure' });
    }

    credentialStore.set(credential.id, {
      ...credential,
      registeredAt: new Date().toISOString(),
    });

    res.status(201).json({
      success: true,
      credentialId: credential.id,
      registeredAt: new Date().toISOString(),
    });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed', message: (error as Error).message });
  }
});

/**
 * POST /api/v1/credentials/verify - Verify a credential
 */
router.post('/verify', async (req, res) => {
  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ error: 'Credential required in request body' });
    }

    const checks: Record<string, { passed: boolean; detail: string }> = {};

    // Structure check
    checks.structure = {
      passed: !!(credential.id && credential.issuer && credential.credentialSubject),
      detail: credential.id ? 'valid' : 'missing required fields',
    };

    // Expiration check
    const now = new Date();
    const exp = new Date(credential.expirationDate);
    checks.expiration = {
      passed: exp > now,
      detail: exp > now ? `valid until ${credential.expirationDate}` : 'expired',
    };

    // Revocation check
    checks.revocation = {
      passed: !revocationSet.has(credential.id),
      detail: revocationSet.has(credential.id) ? 'revoked' : 'not revoked',
    };

    // Proof check
    checks.proof = {
      passed: !!credential.proof?.signature,
      detail: credential.proof ? 'proof present' : 'no proof attached',
    };

    const allPassed = Object.values(checks).every((c) => c.passed);

    res.json({
      valid: allPassed,
      checks,
      verifiedAt: new Date().toISOString(),
      credentialId: credential.id,
    });
  } catch (error) {
    res.status(500).json({ error: 'Verification failed', message: (error as Error).message });
  }
});

/**
 * POST /api/v1/credentials/revoke - Revoke a credential
 */
router.post('/revoke', async (req, res) => {
  const { credentialId, reason } = req.body;

  if (!credentialId) {
    return res.status(400).json({ error: 'credentialId required' });
  }

  revocationSet.add(credentialId);

  res.json({
    success: true,
    credentialId,
    reason: reason || 'unspecified',
    revokedAt: new Date().toISOString(),
  });
});

/**
 * GET /api/v1/credentials/:id/status - Check credential status
 */
router.get('/:id/status', async (req, res) => {
  const credentialId = `urn:agentpass:credential:${req.params.id}`;

  res.json({
    credentialId,
    revoked: revocationSet.has(credentialId),
    registered: credentialStore.has(credentialId),
    checkedAt: new Date().toISOString(),
  });
});

/**
 * GET /api/v1/credentials/:id - Get a registered credential
 */
router.get('/:id', async (req, res) => {
  const credentialId = `urn:agentpass:credential:${req.params.id}`;
  const cred = credentialStore.get(credentialId);

  if (!cred) {
    return res.status(404).json({ error: 'Credential not found' });
  }

  res.json({ credential: cred });
});

export { router as credentialRoutes };
