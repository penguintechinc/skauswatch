# WebUI Dockerfile
# Node.js backend + React frontend shell

# Build stage
FROM node:24-bookworm-slim@sha256:03eae3ef7e88a9de535496fb488d67e02b9d96a063a8967bae657744ecd513f2 AS builder

WORKDIR /app

COPY package*.json ./
COPY .npmrc ./

RUN npm ci

COPY . .

RUN npm run build

# Production stage
FROM node:24-bookworm-slim@sha256:03eae3ef7e88a9de535496fb488d67e02b9d96a063a8967bae657744ecd513f2 AS production

WORKDIR /app

RUN groupadd -r webui && useradd -r -g webui webui

COPY package*.json ./
COPY .npmrc ./

RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/dist ./dist

RUN chown -R webui:webui /app

USER webui

# Env var names/defaults must match what src/server/index.ts actually reads
# (process.env.MANAGER_URL / VAULT_BACKEND_URL / CODESCAN_BACKEND_URL /
# MONITOR_URL) — the old FLASK_API_URL/GO_API_URL vars pointed at
# flask-backend/go-backend, which don't exist post-Rust-port and aren't read
# by any code path. Hosts match the k8s "service name = directory name"
# convention; ports match each Rust service's actual default (manager 5000,
# vault 8080, codescan-backend 5005, monitor 8003) — Helm values override
# these per environment same as any other service.
ENV NODE_ENV=production \
    PORT=3000 \
    MANAGER_URL=http://manager:5000 \
    VAULT_BACKEND_URL=http://vault:8080 \
    CODESCAN_BACKEND_URL=http://codescan-backend:5005 \
    MONITOR_URL=http://monitor:8003

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/healthz', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "dist/server/index.js"]
