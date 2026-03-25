FROM node:18-bookworm-slim@sha256:f9ab18e354e6855ae56ef2b290dd225c1e51a564f87584b9bd21dd651838830e AS builder
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

FROM nginx:stable-bookworm@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
