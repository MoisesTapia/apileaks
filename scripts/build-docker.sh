#!/bin/bash
# APILeak Docker Build Script
# Builds multi-architecture Docker images for APILeak OWASP Enhancement

set -e

# Configuration
IMAGE_NAME="apileak"
VERSION="0.1.0"
PLATFORMS="linux/amd64,linux/arm64"
REGISTRY="${DOCKER_REGISTRY:-}"
PUSH="${PUSH:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
APILeak Docker Build Script

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -v, --version VERSION   Set image version (default: $VERSION)
    -r, --registry REGISTRY Set Docker registry (default: none)
    -p, --push              Push images to registry
    --platforms PLATFORMS   Target platforms (default: $PLATFORMS)
    --no-cache              Build without cache
    --load                  Load image to local Docker (single platform only)

Examples:
    # Build for local development
    $0 --load

    # Build and push to registry
    $0 --registry ghcr.io/myorg --push

    # Build specific version
    $0 --version 1.0.0 --push

Environment Variables:
    DOCKER_REGISTRY         Default registry to use
    PUSH                    Set to 'true' to push by default
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -r|--registry)
            REGISTRY="$2"
            shift 2
            ;;
        -p|--push)
            PUSH="true"
            shift
            ;;
        --platforms)
            PLATFORMS="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --load)
            LOAD="--load"
            PLATFORMS="linux/amd64"  # Load only supports single platform
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Construct full image name
if [[ -n "$REGISTRY" ]]; then
    FULL_IMAGE_NAME="$REGISTRY/$IMAGE_NAME"
else
    FULL_IMAGE_NAME="$IMAGE_NAME"
fi

# Validate Docker and buildx
log_info "Checking Docker and buildx availability..."

if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed or not in PATH"
    exit 1
fi

if ! docker buildx version &> /dev/null; then
    log_error "Docker buildx is not available"
    log_info "Please install Docker buildx or use a newer version of Docker"
    exit 1
fi

# Create buildx builder if it doesn't exist
BUILDER_NAME="apileak-builder"
if ! docker buildx inspect "$BUILDER_NAME" &> /dev/null; then
    log_info "Creating buildx builder: $BUILDER_NAME"
    docker buildx create --name "$BUILDER_NAME" --use
else
    log_info "Using existing buildx builder: $BUILDER_NAME"
    docker buildx use "$BUILDER_NAME"
fi

# Prepare build arguments
BUILD_ARGS=(
    "--platform" "$PLATFORMS"
    "--tag" "$FULL_IMAGE_NAME:$VERSION"
    "--tag" "$FULL_IMAGE_NAME:latest"
    "--file" "Dockerfile"
    "."
)

# Add optional arguments
if [[ -n "$NO_CACHE" ]]; then
    BUILD_ARGS+=("$NO_CACHE")
fi

if [[ -n "$LOAD" ]]; then
    BUILD_ARGS+=("$LOAD")
elif [[ "$PUSH" == "true" ]]; then
    BUILD_ARGS+=("--push")
fi

# Display build information
log_info "Build Configuration:"
echo "  Image Name: $FULL_IMAGE_NAME"
echo "  Version: $VERSION"
echo "  Platforms: $PLATFORMS"
echo "  Registry: ${REGISTRY:-'(local)'}"
echo "  Push: $PUSH"
echo "  Load: ${LOAD:+'true'}"

# Check if Dockerfile exists
if [[ ! -f "Dockerfile" ]]; then
    log_error "Dockerfile not found in current directory"
    exit 1
fi

# Build the image
log_info "Starting Docker build..."
echo "Command: docker buildx build ${BUILD_ARGS[*]}"

if docker buildx build "${BUILD_ARGS[@]}"; then
    log_success "Docker build completed successfully"
else
    log_error "Docker build failed"
    exit 1
fi

# Display image information
if [[ -n "$LOAD" ]]; then
    log_info "Image loaded to local Docker:"
    docker images "$FULL_IMAGE_NAME" | head -2
    
    # Test the image
    log_info "Testing the built image..."
    if docker run --rm "$FULL_IMAGE_NAME:$VERSION" --help > /dev/null 2>&1; then
        log_success "Image test passed"
    else
        log_warning "Image test failed - image may not be working correctly"
    fi
fi

if [[ "$PUSH" == "true" ]]; then
    log_success "Images pushed to registry: $REGISTRY"
    log_info "Available tags:"
    echo "  - $FULL_IMAGE_NAME:$VERSION"
    echo "  - $FULL_IMAGE_NAME:latest"
fi

# Cleanup builder if created
if [[ "$CLEANUP_BUILDER" == "true" ]]; then
    log_info "Cleaning up buildx builder..."
    docker buildx rm "$BUILDER_NAME" || true
fi

log_success "Build process completed!"

# Usage examples
if [[ -n "$LOAD" ]]; then
    echo
    log_info "Usage examples:"
    echo "  # Run directory scan"
    echo "  docker run --rm $FULL_IMAGE_NAME:$VERSION dir --target https://api.example.com"
    echo
    echo "  # Run with custom configuration"
    echo "  docker run --rm -v \$(pwd)/config:/app/config $FULL_IMAGE_NAME:$VERSION full --config config/api-config.yaml"
fi