import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createProxyMiddleware, Options } from 'http-proxy-middleware';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Configuration from environment
const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  managerUrl: process.env.MANAGER_URL || 'http://localhost:5000',
  vaultBackendUrl: process.env.VAULT_BACKEND_URL || 'http://vault-backend:8000',
  codescanBackendUrl: process.env.CODESCAN_BACKEND_URL || 'http://codescan-backend:8080',
  aaaMonitorUrl: process.env.MONITOR_URL || 'http://monitor:8000',
  nodeEnv: process.env.NODE_ENV || 'development',
};

// JSON parsing middleware
app.use(express.json());

// Health check endpoint
app.get('/healthz', (_req: Request, res: Response) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Readiness check
app.get('/readyz', (_req: Request, res: Response) => {
  res.json({ status: 'ready', timestamp: new Date().toISOString() });
});

// Proxy configuration for Manager API (unified auth, users, license features, and all v1 endpoints)
const managerProxyOptions: Options = {
  target: config.managerUrl,
  changeOrigin: true,
  pathRewrite: {
    '^/api': '/api/v1', // Rewrite /api/* to /api/v1/*
  },
  on: {
    proxyReq: (proxyReq, req) => {
      console.log(`[Manager Proxy] ${req.method} ${req.url} -> ${config.managerUrl}`);
    },
    error: (err, _req, res) => {
      console.error('[Manager Proxy Error]', err);
      if (res && 'writeHead' in res) {
        (res as Response).status(502).json({ error: 'Manager API unavailable' });
      }
    },
  },
};

// Proxy configuration for Vault backend
const vaultProxyOptions: Options = {
  target: config.vaultBackendUrl,
  changeOrigin: true,
  pathRewrite: {
    '^/api/vault': '', // Strip /api/vault prefix
  },
  on: {
    proxyReq: (proxyReq, req) => {
      console.log(`[Vault Proxy] ${req.method} ${req.url} -> ${config.vaultBackendUrl}`);
    },
    error: (err, _req, res) => {
      console.error('[Vault Proxy Error]', err);
      if (res && 'writeHead' in res) {
        (res as Response).status(502).json({ error: 'Vault backend unavailable' });
      }
    },
  },
};

// Proxy configuration for CodeScan backend
const codescanProxyOptions: Options = {
  target: config.codescanBackendUrl,
  changeOrigin: true,
  pathRewrite: {
    '^/api/codescan': '', // Strip /api/codescan prefix
  },
  on: {
    proxyReq: (proxyReq, req) => {
      console.log(`[CodeScan Proxy] ${req.method} ${req.url} -> ${config.codescanBackendUrl}`);
    },
    error: (err, _req, res) => {
      console.error('[CodeScan Proxy Error]', err);
      if (res && 'writeHead' in res) {
        (res as Response).status(502).json({ error: 'CodeScan backend unavailable' });
      }
    },
  },
};

// API proxies
// Module-specific proxies (mount before general /api proxy to take precedence)
app.use('/api/vault', createProxyMiddleware(vaultProxyOptions));
app.use('/api/codescan', createProxyMiddleware(codescanProxyOptions));

// Manager backend proxy (unified API for auth, users, license features, and all core endpoints)
app.use('/api', createProxyMiddleware(managerProxyOptions));

// Serve static files in production
if (config.nodeEnv === 'production') {
  const clientDir = path.join(__dirname, '../client');
  app.use(express.static(clientDir));

  // SPA fallback - serve index.html for all non-API routes
  app.get('*', (_req: Request, res: Response) => {
    res.sendFile(path.join(clientDir, 'index.html'));
  });
}

// Error handling middleware
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(config.port, () => {
  console.log(`WebUI server running on port ${config.port}`);
  console.log(`Environment: ${config.nodeEnv}`);
  console.log(`Manager API: ${config.managerUrl}`);
  console.log(`Vault Backend: ${config.vaultBackendUrl}`);
  console.log(`CodeScan Backend: ${config.codescanBackendUrl}`);
  console.log(`Monitor: ${config.aaaMonitorUrl}`);
});
