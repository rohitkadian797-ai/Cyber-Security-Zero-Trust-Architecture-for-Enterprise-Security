import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';

import { initDatabase } from './db/database.js';
import { authRouter } from './routes/auth.routes.js';
import { policyRouter } from './routes/policy.routes.js';
import { resourceRouter } from './routes/resource.routes.js';
import { networkRouter } from './routes/network.routes.js';
import { auditRouter } from './routes/audit.routes.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:5173';

// Initialize SQLite tables if not present
try {
  initDatabase();
  console.log('✅ SQLite Zero Trust database initialized');
} catch (err) {
  console.error('⚠️ Database initialization notice:', err);
}

// Security headers
app.use(helmet());

// CORS configuration for client
app.use(
  cors({
    origin: [CORS_ORIGIN, 'http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:5173'],
    credentials: true,
  })
);

// Logging
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('dev'));
}

// Request parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Global Rate Limiting (Zero Trust defense against brute force)
const limiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX) || 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests from this IP, Zero Trust rate-limiter engaged.' },
});
app.use('/api/', limiter);

// Health check endpoint
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ONLINE',
    service: 'Zero Trust Enterprise Security Engine',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    compliance: ['NIST SP 800-207', 'CISA Zero Trust Maturity Model']
  });
});

// Mount modular API routers
app.use('/api/auth', authRouter);
app.use('/api/policy', policyRouter);
app.use('/api/resources', resourceRouter);
app.use('/api/network', networkRouter);
app.use('/api/audit', auditRouter);

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Endpoint not found on Zero Trust Gateway' });
});

// Centralized error handler
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled Gateway Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error in Security Gateway',
    timestamp: new Date().toISOString()
  });
});

// Start HTTP server
const server = app.listen(PORT, () => {
  console.log(`🛡️  Zero Trust Security Gateway running on port ${PORT}`);
  console.log(`📡 Health Check: http://localhost:${PORT}/api/health`);
  console.log(`🌐 Allowed CORS Origin: ${CORS_ORIGIN}`);
});

export default app;
export { server };
