# WebUI Dockerfile
# Node.js backend + React frontend shell

# Build stage
FROM node:22-bookworm-slim@sha256:4f77a690f2f8946ab16fe1e791a3ac0667ae1c3575c3e4d0d4589e9ed5bfaf3d AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# GitHub Packages authentication
ARG GITHUB_TOKEN
COPY .npmrc ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM node:22-bookworm-slim@sha256:4f77a690f2f8946ab16fe1e791a3ac0667ae1c3575c3e4d0d4589e9ed5bfaf3d AS production

WORKDIR /app

# Create non-root user
RUN groupadd -r webui && useradd -r -g webui webui

# Copy package files and registry config for production dependencies
COPY package*.json ./
ARG GITHUB_TOKEN
COPY .npmrc ./

# Install production dependencies only
RUN npm install --omit=dev && npm cache clean --force

# Copy built assets from builder
COPY --from=builder /app/dist ./dist

# Set ownership
RUN chown -R webui:webui /app

# Switch to non-root user
USER webui

# Environment defaults
ENV NODE_ENV=production \
    PORT=3000 \
    FLASK_API_URL=http://flask-backend:5000 \
    GO_API_URL=http://go-backend:8080

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/healthz || exit 1

# Run the server
CMD ["node", "dist/server/index.js"]
