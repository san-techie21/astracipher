/**
 * Audit Trail API Routes
 *
 * Logs and queries agent actions with cryptographic signatures.
 * This is the data source for compliance report generation.
 */

import { Router } from 'express';
import { z } from 'zod';

const router = Router();

// In-memory store (replace with PostgreSQL + time-series DB)
const auditLog: any[] = [];

const auditEntrySchema = z.object({
  agentDID: z.string(),
  action: z.string(),
  resource: z.string(),
  outcome: z.enum(['success', 'failure', 'denied', 'error']),
  details: z.record(z.unknown()).optional(),
  credentialId: z.string().optional(),
  parentAgentDID: z.string().optional(),
  signature: z.any().optional(),
});

/**
 * POST /api/v1/audit - Log an agent action
 */
router.post('/', async (req, res) => {
  try {
    const entry = auditEntrySchema.parse(req.body);

    const auditEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      ...entry,
      timestamp: new Date().toISOString(),
      serverVerified: true,
    };

    auditLog.push(auditEntry);

    res.status(201).json({
      success: true,
      auditId: auditEntry.id,
      timestamp: auditEntry.timestamp,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation failed', details: error.errors });
    }
    res.status(500).json({ error: 'Audit logging failed' });
  }
});

/**
 * GET /api/v1/audit - Query audit trail
 */
router.get('/', async (req, res) => {
  const {
    agentDID,
    action,
    outcome,
    from,
    to,
    limit = '100',
    offset = '0',
  } = req.query;

  let results = [...auditLog];

  // Filter
  if (agentDID) results = results.filter((e) => e.agentDID === agentDID);
  if (action) results = results.filter((e) => e.action === action);
  if (outcome) results = results.filter((e) => e.outcome === outcome);
  if (from) results = results.filter((e) => e.timestamp >= from);
  if (to) results = results.filter((e) => e.timestamp <= to);

  // Sort newest first
  results.sort((a, b) => b.timestamp.localeCompare(a.timestamp));

  // Paginate
  const total = results.length;
  const l = parseInt(limit as string);
  const o = parseInt(offset as string);
  results = results.slice(o, o + l);

  res.json({
    total,
    limit: l,
    offset: o,
    entries: results,
  });
});

/**
 * GET /api/v1/audit/summary - Get audit summary statistics
 */
router.get('/summary', async (req, res) => {
  const { agentDID, from, to } = req.query;

  let entries = [...auditLog];
  if (agentDID) entries = entries.filter((e) => e.agentDID === agentDID);
  if (from) entries = entries.filter((e) => e.timestamp >= from);
  if (to) entries = entries.filter((e) => e.timestamp <= to);

  const summary = {
    totalActions: entries.length,
    outcomes: {
      success: entries.filter((e) => e.outcome === 'success').length,
      failure: entries.filter((e) => e.outcome === 'failure').length,
      denied: entries.filter((e) => e.outcome === 'denied').length,
      error: entries.filter((e) => e.outcome === 'error').length,
    },
    uniqueAgents: new Set(entries.map((e) => e.agentDID)).size,
    topActions: getTopActions(entries),
    period: {
      from: entries.length > 0 ? entries[entries.length - 1].timestamp : null,
      to: entries.length > 0 ? entries[0].timestamp : null,
    },
  };

  res.json(summary);
});

function getTopActions(entries: any[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const entry of entries) {
    counts[entry.action] = (counts[entry.action] || 0) + 1;
  }
  return Object.fromEntries(
    Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10)
  );
}

export { router as auditRoutes };
