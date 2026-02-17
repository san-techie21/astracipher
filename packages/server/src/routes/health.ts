import { Router } from 'express';

const router = Router();
const startTime = Date.now();

router.get('/', (_req, res) => {
  res.json({
    status: 'healthy',
    version: '0.1.0',
    uptime: Math.floor((Date.now() - startTime) / 1000),
    timestamp: new Date().toISOString(),
    services: {
      didRegistry: 'operational',
      credentialVerification: 'operational',
      auditTrail: 'operational',
    },
  });
});

router.get('/ready', (_req, res) => {
  // In production: check DB connection, external dependencies
  res.json({ ready: true });
});

export { router as healthRoutes };
