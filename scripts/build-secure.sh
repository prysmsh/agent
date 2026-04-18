#!/bin/bash
set -euo pipefail

# Build script for prysm-agent image
# Usage: ./scripts/build-secure.sh

REPO="${DOCKER_REPO:-ghcr.io/prysmsh/agent}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo latest)}"

echo "Building prysm-agent image..."
echo "Repository: $REPO"
echo "Version: $VERSION"
echo ""

docker build \
    -t "${REPO}:${VERSION}" \
    -t "${REPO}:latest" \
    -f Dockerfile \
    .

echo "✅ Image built: ${REPO}:${VERSION}"
echo ""

if command -v trivy &> /dev/null; then
    echo "🔍 Scanning image for vulnerabilities..."
    trivy image \
        --severity CRITICAL,HIGH \
        --exit-code 0 \
        "${REPO}:${VERSION}"
else
    echo "⚠️  Trivy not installed. Skipping scan."
    echo "   Install with: brew install trivy (macOS) or apt-get install trivy (Debian/Ubuntu)"
fi

echo ""
echo "✅ Build complete!"
docker images "${REPO}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
echo ""
echo "To push: docker push ${REPO}:${VERSION}"
