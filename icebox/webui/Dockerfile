FROM node:18-bookworm-slim@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb AS builder
WORKDIR /app

# Copy .npmrc for GitHub Packages registry config (@penguintechinc scope)
COPY .npmrc ./
COPY package*.json ./

# Inject GitHub token at build time for private package access; remove afterward
ARG GITHUB_TOKEN
RUN echo "//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}" >> .npmrc \
    && npm ci \
    && rm -f .npmrc

COPY . .
RUN npm run build

FROM nginx:stable-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb
COPY --chown=nginx:nginx --from=builder /app/dist /usr/share/nginx/html
COPY --chown=nginx:nginx nginx.conf /etc/nginx/conf.d/default.conf
# nginx image ships with a built-in 'nginx' non-root user (UID 101).
# Nginx master process must start as root to bind port 80, then workers
# drop to the 'nginx' user as configured in nginx.conf (user nginx;).
# Ensure nginx.conf contains: user nginx; and pid /tmp/nginx.pid;
RUN chown -R nginx:nginx /var/cache/nginx /var/log/nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && chown nginx:nginx /var/run/nginx.pid
EXPOSE 80
USER nginx
CMD ["nginx", "-g", "daemon off;"]
