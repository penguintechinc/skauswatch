FROM node:18-bookworm-slim AS builder
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

FROM nginx:stable-bookworm-slim
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
