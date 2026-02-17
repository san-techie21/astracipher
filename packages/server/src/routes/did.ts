/**
 * DID Registry API Routes
 */

import { Router } from 'express';
import { z } from 'zod';
import { DIDManager } from '@agentpass/core';
import { AgentPassCrypto } from '@agentpass/crypto';

const router = Router();

// In-memory store (replace with PostgreSQL in production)
const didStore = new Map<string, any>();

const createDIDSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  network: z.string().default('testnet'),
  controller: z.string().optional(),
  services: z.array(z.object({
    id: z.string(),
    type: z.string(),
    serviceEndpoint: z.string(),
  })).optional(),
});

/**
 * POST /api/v1/did - Register a new DID
 */
router.post('/', async (req, res) => {
  try {
    const body = createDIDSchema.parse(req.body);
    const crypto = new AgentPassCrypto();
    const didManager = new DIDManager(crypto);

    const { did, keys } = await didManager.createDID({
      network: body.network,
      controller: body.controller,
      services: body.services,
    });

    // Store in registry
    didStore.set(did.id, did);

    // Return DID document (keys returned separately for security)
    res.status(201).json({
      success: true,
      did: did,
      didId: did.id,
      // In production, keys would be returned encrypted or via secure channel
      keyId: 'pqc' in keys ? (keys as any).keyId : keys.keyId,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation failed', details: error.errors });
    }
    res.status(500).json({ error: 'DID creation failed', message: (error as Error).message });
  }
});

/**
 * GET /api/v1/did/:did - Resolve a DID
 */
router.get('/:did(*)', async (req, res) => {
  const didId = req.params.did;

  const didDoc = didStore.get(didId);
  if (!didDoc) {
    return res.status(404).json({ error: 'DID not found', did: didId });
  }

  if (didDoc.deactivated) {
    return res.status(410).json({ error: 'DID deactivated', did: didId });
  }

  res.json({ did: didDoc });
});

/**
 * PUT /api/v1/did/:did - Update a DID document
 */
router.put('/:did(*)', async (req, res) => {
  const didId = req.params.did;
  const existing = didStore.get(didId);

  if (!existing) {
    return res.status(404).json({ error: 'DID not found' });
  }

  // In production: verify the update is signed by the controller
  const updated = {
    ...existing,
    ...req.body,
    id: didId, // prevent ID change
    updated: new Date().toISOString(),
  };

  didStore.set(didId, updated);
  res.json({ success: true, did: updated });
});

/**
 * DELETE /api/v1/did/:did - Deactivate a DID
 */
router.delete('/:did(*)', async (req, res) => {
  const didId = req.params.did;
  const existing = didStore.get(didId);

  if (!existing) {
    return res.status(404).json({ error: 'DID not found' });
  }

  existing.deactivated = true;
  existing.updated = new Date().toISOString();
  didStore.set(didId, existing);

  res.json({ success: true, message: 'DID deactivated' });
});

/**
 * GET /api/v1/did - List registered DIDs (paginated)
 */
router.get('/', async (req, res) => {
  const limit = parseInt(req.query.limit as string) || 50;
  const offset = parseInt(req.query.offset as string) || 0;

  const all = [...didStore.entries()]
    .filter(([_, doc]) => !doc.deactivated)
    .slice(offset, offset + limit);

  res.json({
    total: didStore.size,
    limit,
    offset,
    dids: all.map(([id, doc]) => ({
      id,
      controller: doc.controller,
      created: doc.created,
      updated: doc.updated,
    })),
  });
});

export { router as didRoutes };
