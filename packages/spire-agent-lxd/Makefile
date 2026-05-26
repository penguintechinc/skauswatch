.PHONY: build clean

SPIRE_VERSION ?= 1.9.4
DOCKER_BUILDX_PLATFORMS ?= linux/amd64,linux/arm64
REGISTRY ?= ghcr.io/penguintechinc/skauswatch
IMAGE_NAME ?= spire-agent-lxd
DIST_DIR ?= dist

build:
	@echo "Building .deb packages for $(DOCKER_BUILDX_PLATFORMS)..."
	docker buildx build \
		--platform $(DOCKER_BUILDX_PLATFORMS) \
		--build-arg SPIRE_VERSION=$(SPIRE_VERSION) \
		--output type=oci,dest=$(DIST_DIR) \
		-t $(REGISTRY)/$(IMAGE_NAME):$(SPIRE_VERSION) \
		-f Dockerfile .
	@echo "Packages built to $(DIST_DIR)/"

clean:
	@echo "Cleaning $(DIST_DIR)..."
	rm -rf $(DIST_DIR)
	@echo "Clean complete."
