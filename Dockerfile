FROM golang:1.24-alpine3.21 AS builder

# Install build dependencies
RUN apk add --no-cache git

WORKDIR /app

# Copy go mod files and local pkg module (use prysmsh-pkg to avoid clashing with agent's pkg/)
COPY prysm-agent/go.mod prysm-agent/go.sum ./
COPY pkg/ ./prysmsh-pkg/

# Copy source code
COPY prysm-agent/ .

# Use local pkg module (avoids fetching from network; pkg is in the same repo)
RUN echo 'replace github.com/prysmsh/pkg => ./prysmsh-pkg' >> go.mod

RUN go mod download

# Build the agent binary with security hardening
RUN CGO_ENABLED=0 GOOS=linux go build \
    -a \
    -installsuffix cgo \
    -ldflags="-s -w -extldflags '-static'" \
    -trimpath \
    -o prysm-agent ./cmd/agent

# Final stage - use specific Alpine version for security patches
FROM alpine:3.21

# Install runtime dependencies with pinned versions
RUN apk add --no-cache \
    curl \
    ca-certificates \
    wireguard-tools \
    iptables \
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
RUN TRIVY_VERSION="0.58.2" && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

# Create non-root user
RUN addgroup -g 1001 prysm \
    && adduser -D -u 1001 -G prysm prysm

# Create necessary directories (including /app/tmp for Trivy and subprocess temp files)
RUN mkdir -p /var/log/kubeaccess \
    /var/lib/prysm-agent \
    /app/tmp \
    && chown -R prysm:prysm /var/log/kubeaccess /var/lib/prysm-agent /app/tmp

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /app/prysm-agent .

# Copy configuration templates
COPY prysm-agent/config/ ./config/

# Set up environment
ENV CLUSTER_ID=""
ENV AGENT_TOKEN=""
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

# Switch to non-root user for security
USER prysm

EXPOSE 8080

CMD ["./prysm-agent"]
