DOCKER_IMAGE_NAME := sigstore-php-protoc-builder
PROTO_OUTPUT_DIR := ./src/Proto

.PHONY: default
default: generate-protos

.PHONY: generate-protos
generate-protos: build-protoc-image
	@echo "Generating PHP classes from protos..."
	@docker run --rm -v ${PWD}/src:/out $(DOCKER_IMAGE_NAME)
	@echo "Proto generation complete."

.PHONY: build-protoc-image
build-protoc-image:
	@echo "Building protoc Docker image $(DOCKER_IMAGE_NAME)..."
	@docker build -t $(DOCKER_IMAGE_NAME) -f Dockerfile.protoc .

.PHONY: clean-protos
clean-protos:
	@echo "Cleaning generated proto classes..."
	@rm -rf $(PROTO_OUTPUT_DIR)
	@mkdir -p $(PROTO_OUTPUT_DIR)

.PHONY: all
all: clean-protos generate-protos