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
  iceboxBackendUrl: process.env.ICEBOX_BACKEND_URL || 'http://icebox-backend:8000',
  darwinBackendUrl: process.env.DARWIN_BACKEND_URL || 'http://darwin-backend:8080',
  aaaMonitorUrl: process.env.AAA_MONITOR_URL || 'http://aaa-monitor:8000',
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

// Proxy configuration for IceBox backend
const iceboxProxyOptions: Options = {
  target: config.iceboxBackendUrl,
  changeOrigin: true,
  pathRewrite: {
    '^/api/icebox': '', // Strip /api/icebox prefix
  },
  on: {
    proxyReq: (proxyReq, req) => {
      console.log(`[IceBox Proxy] ${req.method} ${req.url} -> ${config.iceboxBackendUrl}`);
    },
    error: (err, _req, res) => {
      console.error('[IceBox Proxy Error]', err);
      if (res && 'writeHead' in res) {
        (res as Response).status(502).json({ error: 'IceBox backend unavailable' });
      }
    },
  },
};

// Proxy configuration for Darwin backend
const darwinProxyOptions: Options = {
  target: config.darwinBackendUrl,
  changeOrigin: true,
  pathRewrite: {
    '^/api/darwin': '', // Strip /api/darwin prefix
  },
  on: {
    proxyReq: (proxyReq, req) => {
      console.log(`[Darwin Proxy] ${req.method} ${req.url} -> ${config.darwinBackendUrl}`);
    },
    error: (err, _req, res) => {
      console.error('[Darwin Proxy Error]', err);
      if (res && 'writeHead' in res) {
        (res as Response).status(502).json({ error: 'Darwin backend unavailable' });
      }
    },
  },
};

// API proxies
// Module-specific proxies (mount before general /api proxy to take precedence)
app.use('/api/icebox', createProxyMiddleware(iceboxProxyOptions));
app.use('/api/darwin', createProxyMiddleware(darwinProxyOptions));

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
  console.log(`IceBox Backend: ${config.iceboxBackendUrl}`);
  console.log(`Darwin Backend: ${config.darwinBackendUrl}`);
  console.log(`AAA Monitor: ${config.aaaMonitorUrl}`);
});
