ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

WORKDIR /app

# Copy go mod files and local pkg module (use prysm-pkg to avoid clashing with agent's pkg/)
COPY prysm-agent/go.mod prysm-agent/go.sum ./
COPY pkg/ ./prysm-pkg/

# Copy source code
COPY prysm-agent/ .

# Use local pkg module (avoids fetching from network; pkg is in the same repo).
# pqc and tlsutil are separate Go modules on the registry but plain packages
# locally, so we create stub go.mod files and add replace directives for all three.
RUN printf 'module github.com/prysmsh/pkg/pqc\ngo 1.26.0\n' > ./prysm-pkg/pqc/go.mod \
    && printf 'module github.com/prysmsh/pkg/tlsutil\ngo 1.26.0\n' > ./prysm-pkg/tlsutil/go.mod \
    && printf '\nreplace github.com/prysmsh/pkg => ./prysm-pkg\nreplace github.com/prysmsh/pkg/pqc => ./prysm-pkg/pqc\nreplace github.com/prysmsh/pkg/tlsutil => ./prysm-pkg/tlsutil\n' >> go.mod

RUN go mod download
# Ensure go.sum has all transitive deps (needed when using replace with local pkg)
RUN go get ./cmd/agent

# Build the agent binary with security hardening
RUN CGO_ENABLED=0 GOOS=linux go build \
    -a \
    -installsuffix cgo \
    -ldflags="-s -w -extldflags '-static'" \
    -trimpath \
    -o prysm-agent ./cmd/agent

# Build the nethelper binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -a \
    -installsuffix cgo \
    -ldflags="-s -w -extldflags '-static'" \
    -trimpath \
    -o prysm-nethelper ./cmd/nethelper

# Final stage - use specific Alpine version for security patches
FROM alpine:3.21

# Install runtime dependencies with pinned versions
RUN apk add --no-cache \
    curl \
    ca-certificates \
    wireguard-tools \
    iptables \
    su-exec \
    && rm -rf /var/cache/apk/*

# Install kubectl with specific version
RUN KUBECTL_VERSION="v1.32.0" && \
    curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl.sha256" \
    && echo "$(cat kubectl.sha256)  kubectl" | sha256sum -c - \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/ \
    && rm kubectl.sha256

# Install Trivy for container vulnerability scanning
RUN TRIVY_VERSION="0.69.1" && \
    TRIVY_OS="Linux" && \
    TRIVY_ARCH="64bit" && \
    TRIVY_TARBALL="trivy_${TRIVY_VERSION}_${TRIVY_OS}-${TRIVY_ARCH}.tar.gz" && \
    curl -fsSL -o /tmp/trivy.tar.gz "https://get.trivy.dev/trivy?os=${TRIVY_OS}&arch=${TRIVY_ARCH}&version=${TRIVY_VERSION}&type=tar.gz&client=docker-build" && \
    curl -fsSL -o /tmp/trivy_checksums.txt "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" && \
    grep "${TRIVY_TARBALL}" /tmp/trivy_checksums.txt | awk '{print $1 "  /tmp/trivy.tar.gz"}' | sha256sum -c - && \
    tar -xzf /tmp/trivy.tar.gz -C /tmp trivy && \
    install /tmp/trivy /usr/local/bin/trivy && \
    rm -f /tmp/trivy /tmp/trivy.tar.gz /tmp/trivy_checksums.txt

# Create non-root user
RUN addgroup -g 1001 prysm \
    && adduser -D -u 1001 -G prysm prysm

# Create necessary directories (including /app/tmp for Trivy and subprocess temp files)
RUN mkdir -p /var/log/kubeaccess \
    /var/lib/prysm-agent \
    /app/tmp \
    /var/run/prysm \
    && chown -R prysm:prysm /var/log/kubeaccess /var/lib/prysm-agent /app/tmp

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /app/prysm-agent .
COPY --from=builder /app/prysm-nethelper .

# Copy configuration templates
COPY prysm-agent/config/ ./config/

# Copy entrypoint
COPY prysm-agent/entrypoint.sh .
RUN chmod +x entrypoint.sh

# Set up environment
ENV CLUSTER_ID=""
ENV ORGANIZATION_ID=1
ENV BACKEND_URL="http://kubeaccess-backend:8080"
ENV REGION="us-east-1"
ENV DERP_SERVER="wss://derp.kubeaccess.com/derp"
ENV LOG_LEVEL="info"

# Logging environment variables
ENV ENABLE_LOGGING=true
ENV LOG_INGESTION_URL=""
ENV USE_PRIVATE_LINK=false
ENV LOG_SOURCES="pod,event,system"
ENV LOG_LEVELS="info,warn,error,fatal"
ENV LOG_BATCH_SIZE=100
ENV LOG_COLLECTION_INTERVAL=30s

# Health check ensures the agent process is still running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep prysm-agent >/dev/null || exit 1

EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
