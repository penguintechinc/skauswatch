# WebUI Dockerfile
# Node.js backend + React frontend shell

# Build stage
FROM node:22-bookworm-slim AS builder

ARG BUILD_TIME
ENV VITE_BUILD_TIME=${BUILD_TIME}

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application with build time embedded
RUN npm run build && \
    echo "WebUI built at: ${BUILD_TIME:-unknown}"

# Production stage
FROM node:22-bookworm-slim AS production

ARG BUILD_TIME
ENV BUILD_TIME=${BUILD_TIME}

WORKDIR /app

# Create non-root user
RUN groupadd -r webui && useradd -r -g webui webui

# Copy package files for production dependencies
COPY package*.json ./

# Install production dependencies only
RUN npm ci --omit=dev && npm cache clean --force

# Copy built assets from builder
COPY --from=builder /app/dist ./dist

# Create build info file
RUN echo "{\"buildTime\":\"${BUILD_TIME:-unknown}\",\"buildDate\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > /app/dist/build-info.json

# Set ownership
RUN chown -R webui:webui /app

# Switch to non-root user
USER webui

# Environment defaults
ENV NODE_ENV=production \
    PORT=3000 \
    FLASK_API_URL=http://flask-backend:5000

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/healthz || exit 1

# Run the server
CMD ["node", "dist/server/index.js"]
