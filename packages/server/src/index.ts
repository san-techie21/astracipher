/**
 * AgentPass Verification Server
 *
 * Hosted service providing:
 * - DID Registry (create, resolve, update, deactivate)
 * - Credential Verification (verify, check status)
 * - Revocation Registry (revoke, check revocation)
 * - Audit Trail (log, query)
 * - Health & Metrics
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { rateLimit } from 'express-rate-limit';
import pino from 'pino';
import { config } from 'dotenv';

import { didRoutes } from './routes/did.js';
import { credentialRoutes } from './routes/credentials.js';
import { auditRoutes } from './routes/audit.js';
import { healthRoutes } from './routes/health.js';

config(); // Load .env

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV !== 'production'
    ? { target: 'pino-pretty' }
    : undefined,
});

const app = express();
const port = parseInt(process.env.PORT || '3456');

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-AgentPass-Key'],
}));
app.use(compression());
app.use(express.json({ limit: '1mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: parseInt(process.env.RATE_LIMIT || '100'),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});
app.use('/api/', limiter);

// Request logging
app.use((req, _res, next) => {
  logger.info({ method: req.method, url: req.url }, 'request');
  next();
});

// API Routes
app.use('/api/v1/did', didRoutes);
app.use('/api/v1/credentials', credentialRoutes);
app.use('/api/v1/audit', auditRoutes);
app.use('/health', healthRoutes);

// Root
app.get('/', (_req, res) => {
  res.json({
    name: 'AgentPass Verification Server',
    version: '0.1.0',
    protocol: 'agentpass/0.1',
    docs: 'https://agentpass.dev/docs/api',
    endpoints: {
      did: '/api/v1/did',
      credentials: '/api/v1/credentials',
      audit: '/api/v1/audit',
      health: '/health',
    },
  });
});

// Error handler
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error({ err }, 'unhandled error');
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV !== 'production' ? err.message : undefined,
  });
});

// Start
app.listen(port, () => {
  logger.info(`AgentPass server running on port ${port}`);
  logger.info(`Network: ${process.env.NETWORK || 'testnet'}`);
  logger.info(`API: http://localhost:${port}/api/v1`);
});

export { app };
