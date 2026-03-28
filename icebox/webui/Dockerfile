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
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
