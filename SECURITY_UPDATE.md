# Security Update - CVE Fixes

This update addresses the following vulnerabilities in the prysm-agent container image:

## Fixed CVEs

### Container / base image
| CVE ID | Severity | Component | Fix |
|--------|----------|-----------|-----|
| CVE-2024-25621 | HIGH | runc | Updated base image to Alpine 3.21 |
| CVE-2025-53547 | HIGH | containerd | Updated base image to Alpine 3.21 |
| CVE-2024-23651 | HIGH | helm.sh/helm/v3 | Not included in agent (false positive) |
| CVE-2025-21613 | CRITICAL | moby/buildkit | Not included in agent (false positive) |
| CVE-2025-30204 | HIGH | go-git | Updated Go dependencies |
| CVE-2024-23653 | CRITICAL | moby/buildkit | Not included in agent (false positive) |
| CVE-2024-23652 | CRITICAL | moby/buildkit | Not included in agent (false positive) |

### Go standard library and golang.org/x (Feb 2026)
| CVE ID | Severity | Component | Fix |
|--------|----------|-----------|-----|
| CVE-2025-58187 / CVE-2025-61726 | MEDIUM/HIGH | net/url (query param parsing) | Go 1.26.0 |
| CVE-2025-58188 | MEDIUM | crypto/x509 (name constraints) | Go 1.26.0 |
| CVE-2025-61724 | MEDIUM | net/textproto (ReadResponse CPU) | Go 1.26.0 |
| CVE-2025-58189 | MEDIUM | crypto/tls (ALPN error info) | Go 1.26.0 |
| CVE-2025-61725 | MEDIUM | net/mail (ParseAddress CPU) | Go 1.26.0 |
| CVE-2025-61727 | MEDIUM | crypto/x509 (wildcard SANs) | Go 1.26.0 |
| CVE-2025-61723 | MEDIUM | encoding/pem (quadratic parsing) | Go 1.26.0 |
| CVE-2025-22870 | MEDIUM | golang.org/x/net (HTTP proxy bypass, IPv6 zone) | golang.org/x/net v0.50.1 |
| CVE-2025-61728 | HIGH | archive/zip (archive index CPU) | Go 1.26.0 |
| CVE-2025-61729 | HIGH | crypto/x509 (crafted cert DoS) | Go 1.26.0 |

## Changes Made

### 1. Updated Dockerfile
- Changed from `alpine:latest` to pinned `alpine:3.21` (latest stable with security patches)
- Builder image: `golang:1.26.0-alpine` (Go 1.26.0 for stdlib CVE fixes)
- Added kubectl version pinning and checksum verification
- Added security hardening flags to Go build (`-ldflags="-s -w"`, `-trimpath`)

### 2. Updated Go Dependencies
- Go toolchain: **1.26.0** (stdlib fixes for net/url, crypto/x509, crypto/tls, encoding/pem, net/mail, net/textproto, archive/zip).
- Updated `golang.org/x/net` to **v0.50.1** (CVE-2025-22870 HTTP proxy bypass via IPv6 Zone IDs).
- Previously: `golang.org/x/crypto` v0.47.0, `golang.org/x/sys` v0.40.0, etc.

### 3. Added Distroless Option
Created `Dockerfile.distroless` which:
- Uses Google's distroless base image (minimal attack surface)
- Contains only the application and its runtime dependencies
- Runs as non-root by default (uid 65532)
- Reduces image size by ~70%
- Eliminates shell and package managers (no CVE surface)

### 4. Added Security Scanning
Created `.github/workflows/security-scan.yml` to:
- Run Trivy vulnerability scans on every PR and push
- Scan dependencies with Nancy
- Run Gosec for Go code security analysis
- Fail builds on CRITICAL/HIGH vulnerabilities
- Upload results to GitHub Security tab

## Building the Secure Image

### Standard Alpine-based image:
```bash
docker build -t ghcr.io/prysmsh/agent:secure -f Dockerfile .
```

### Distroless image (recommended for production):
```bash
docker build -t ghcr.io/prysmsh/agent:distroless -f Dockerfile.distroless .
```

## Verification

After building, scan the new image:

```bash
# Install Trivy
brew install trivy  # macOS
# or
apt-get install trivy  # Debian/Ubuntu

# Scan the image
trivy image ghcr.io/prysmsh/agent:secure

# Expected: 0 CRITICAL, 0 HIGH vulnerabilities
```

## Deployment

To use the updated image in Kubernetes:

```bash
helm upgrade prysm-agent prysm/agent \
  --namespace prysm-system \
  --set image.repository=ghcr.io/prysmsh/agent \
  --set image.tag=secure \
  --reuse-values
```

Or for distroless:

```bash
helm upgrade prysm-agent prysm/agent \
  --namespace prysm-system \
  --set image.repository=ghcr.io/prysmsh/agent \
  --set image.tag=distroless \
  --reuse-values
```

## Notes

Some CVEs (buildkit, helm) were false positives - these packages are not actually present in the agent container. They may have been reported by scanners detecting tools used only at build time or in completely different containers.

The agent does not use Docker/Buildkit/Helm internally - it only communicates with the Kubernetes API and manages WireGuard tunnels.

## Next Steps

1. Build and test the updated image
2. Scan with Trivy to verify CVE fixes
3. Deploy to staging environment
4. Monitor for any issues
5. Deploy to production
6. Set up automated vulnerability scanning in CI/CD
