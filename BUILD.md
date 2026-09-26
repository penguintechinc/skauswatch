# SkausWatch Build and Deployment Guide

This document provides comprehensive instructions for building and deploying SkausWatch Docker containers.

## Building Docker Images

### Prerequisites

- Docker 24.0+
- Docker BuildKit enabled
- At least 4GB RAM for builds
- At least 10GB disk space

### Build Arguments

The Dockerfiles support several build arguments:

| Argument | Description | Example |
|----------|-------------|---------|
| `BUILD_DATE` | Build timestamp | `2024-01-15T10:30:00Z` |
| `VERSION` | Application version | `0.1.0` |
| `VCS_REF` | Git commit hash | `a1b2c3d` |

### Building Individual Services

#### Manager Service
```bash
# Development build
docker build -f services/manager/Dockerfile \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  --build-arg VERSION=0.1.0 \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  -t skauswatch/manager:0.1.0 \
  -t skauswatch/manager:latest .

# Multi-architecture build
docker buildx build --platform linux/amd64,linux/arm64 \
  -f services/manager/Dockerfile \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  --build-arg VERSION=0.1.0 \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  -t skauswatch/manager:0.1.0 \
  --push .
```

#### PKI Server Service
```bash
docker build -f services/pki/Dockerfile \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  --build-arg VERSION=0.1.0 \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  -t skauswatch/pki:0.1.0 \
  -t skauswatch/pki:latest .
```

#### SSH CA Service
```bash
docker build -f services/sshca/Dockerfile \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  --build-arg VERSION=0.1.0 \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  -t skauswatch/sshca:0.1.0 \
  -t skauswatch/sshca:latest .
```

#### Monitor Service
```bash
docker build -f services/monitor/Dockerfile \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  --build-arg VERSION=0.1.0 \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  -t skauswatch/monitor:0.1.0 \
  -t skauswatch/monitor:latest .
```

### Building All Services

Use the provided build script for convenience:

```bash
#!/bin/bash
# build-all.sh

set -e

# Build variables
BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
VERSION=${VERSION:-0.1.0}
VCS_REF=$(git rev-parse --short HEAD)
REGISTRY=${REGISTRY:-skauswatch}

# Services to build
SERVICES=("manager" "pki" "sshca" "monitor")

echo "Building SkausWatch services..."
echo "Build Date: $BUILD_DATE"
echo "Version: $VERSION"
echo "VCS Ref: $VCS_REF"
echo "Registry: $REGISTRY"

for service in "${SERVICES[@]}"; do
    echo "Building $service..."
    docker build \
        -f services/$service/Dockerfile \
        --build-arg BUILD_DATE="$BUILD_DATE" \
        --build-arg VERSION="$VERSION" \
        --build-arg VCS_REF="$VCS_REF" \
        -t "$REGISTRY/$service:$VERSION" \
        -t "$REGISTRY/$service:latest" \
        .
    echo "✓ Built $service"
done

echo "All services built successfully!"
```

Make it executable and run:
```bash
chmod +x build-all.sh
./build-all.sh
```

## Docker Compose Build

The docker-compose.yml file includes build configurations:

```bash
# Build and start all services
docker-compose up --build -d

# Build specific service
docker-compose build manager

# Force rebuild without cache
docker-compose build --no-cache
```

## Multi-Architecture Builds

For production deployments targeting multiple architectures:

```bash
# Create and use buildx builder
docker buildx create --name multiarch --use
docker buildx inspect --bootstrap

# Build and push multi-arch images
for service in manager pki sshca monitor; do
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        -f services/$service/Dockerfile \
        --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
        --build-arg VERSION=0.1.0 \
        --build-arg VCS_REF=$(git rev-parse --short HEAD) \
        -t skauswatch/$service:0.1.0 \
        -t skauswatch/$service:latest \
        --push .
done
```

## Security Best Practices

### Image Security

1. **Non-root user**: All images run as non-root user (65534)
2. **Minimal base images**: Using Python 3.13 slim images
3. **Multi-stage builds**: Reducing final image size
4. **Security updates**: Regular base image updates
5. **No secrets in images**: Secrets provided via environment variables

### Scanning Images

```bash
# Scan for vulnerabilities (using Trivy)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy image skauswatch/manager:0.1.0

# Scan all built images
for service in manager pki sshca monitor; do
    echo "Scanning $service..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        aquasec/trivy image skauswatch/$service:0.1.0
done
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build and Deploy SkausWatch

on:
  push:
    branches: [main]
    tags: ['v*']
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    strategy:
      matrix:
        service: [manager, pki, sshca, monitor]

    steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3

    - name: Log in to Container Registry
      if: github.event_name != 'pull_request'
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}/${{ matrix.service }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=semver,pattern={{version}}
          type=semver,pattern={{major}}.{{minor}}

    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        file: services/${{ matrix.service }}/Dockerfile
        platforms: linux/amd64,linux/arm64
        push: ${{ github.event_name != 'pull_request' }}
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        build-args: |
          BUILD_DATE=${{ steps.meta.outputs.labels }}
          VERSION=${{ steps.meta.outputs.version }}
          VCS_REF=${{ github.sha }}
```

### GitLab CI Example

```yaml
stages:
  - build
  - test
  - deploy

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: "/certs"

.docker-build: &docker-build
  stage: build
  image: docker:24-dind
  services:
    - docker:24-dind
  before_script:
    - echo $CI_REGISTRY_PASSWORD | docker login -u $CI_REGISTRY_USER --password-stdin $CI_REGISTRY
  script:
    - |
      docker build \
        -f services/$SERVICE_NAME/Dockerfile \
        --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
        --build-arg VERSION=$CI_COMMIT_TAG \
        --build-arg VCS_REF=$CI_COMMIT_SHORT_SHA \
        -t $CI_REGISTRY_IMAGE/$SERVICE_NAME:$CI_COMMIT_TAG \
        -t $CI_REGISTRY_IMAGE/$SERVICE_NAME:latest .
    - docker push $CI_REGISTRY_IMAGE/$SERVICE_NAME:$CI_COMMIT_TAG
    - docker push $CI_REGISTRY_IMAGE/$SERVICE_NAME:latest

build-manager:
  <<: *docker-build
  variables:
    SERVICE_NAME: manager

build-pki:
  <<: *docker-build
  variables:
    SERVICE_NAME: pki

build-sshca:
  <<: *docker-build
  variables:
    SERVICE_NAME: sshca

build-monitor:
  <<: *docker-build
  variables:
    SERVICE_NAME: monitor
```

## Performance Optimization

### Build Performance

1. **Use .dockerignore**: Exclude unnecessary files
2. **Layer caching**: Optimize layer order
3. **Multi-stage builds**: Reduce final image size
4. **Build cache**: Use BuildKit cache mounts

### Runtime Performance

1. **Resource limits**: Set appropriate CPU/memory limits
2. **Health checks**: Configure proper health check intervals
3. **Logging**: Use structured logging with appropriate levels
4. **Monitoring**: Enable metrics collection

## Troubleshooting

### Build Issues

```bash
# Clean Docker build cache
docker builder prune -a

# Remove all images and rebuild
docker image prune -a
docker system prune -a

# Build with no cache
docker build --no-cache -f services/manager/Dockerfile .
```

### Runtime Issues

```bash
# Check container logs
docker logs container-name

# Execute into container
docker exec -it container-name /bin/bash

# Check resource usage
docker stats

# Inspect container configuration
docker inspect container-name
```

### Image Analysis

```bash
# Analyze image layers
docker history skauswatch/manager:0.1.0

# Check image size
docker images | grep skauswatch

# Dive into image contents
docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock \
    wagoodman/dive:latest skauswatch/manager:0.1.0
```

## Deployment Verification

After building and deploying:

1. **Health checks**: Verify all services are healthy
2. **Connectivity**: Test inter-service communication
3. **Functionality**: Run integration tests
4. **Performance**: Monitor resource usage
5. **Security**: Scan for vulnerabilities

```bash
# Quick health check script
#!/bin/bash
services=("manager:8000" "pki:8001" "sshca:8002" "monitor:8003")

for service in "${services[@]}"; do
    name="${service%:*}"
    port="${service#*:}"
    echo -n "Checking $name... "
    if curl -sf "http://localhost:$port/health" > /dev/null; then
        echo "✓ Healthy"
    else
        echo "✗ Unhealthy"
    fi
done
```

## Support

For build and deployment issues:

- Check logs first: `docker-compose logs -f`
- Review configuration: Environment variables and secrets
- Verify prerequisites: Docker version, resource availability
- Consult documentation: https://docs.skauswatch.io
- Contact support: support@skauswatch.io