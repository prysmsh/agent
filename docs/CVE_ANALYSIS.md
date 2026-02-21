# CVE Analysis for prysm-agent Container

This document analyzes CVEs reported by vulnerability scanners and explains which are real issues vs. false positives.

## Summary

| Total CVEs | Real Issues | False Positives | Fixed |
|------------|-------------|-----------------|-------|
| 13 | 2 | 11 | 2 |

## CVE Breakdown

### ✅ Fixed - Real Issues

| CVE | Severity | Component | Fix |
|-----|----------|-----------|-----|
| CVE-2025-22868 | HIGH | golang.org/x/oauth2/jws | Updated oauth2 v0.30.0 → v0.34.0 |
| CVE-2025-30204 | HIGH | Various Go packages | Updated golang.org/x/* packages |

### ❌ False Positives - Not In Agent

These packages are **not included** in the agent container and are incorrectly reported by scanners:

| CVE | Severity | Component | Why It's a False Positive |
|-----|----------|-----------|---------------------------|
| CVE-2025-26519 | HIGH | hashicorp/go-getter | Not a dependency - `go list -m all` shows it's not included |
| CVE-2024-23651 | HIGH | helm.sh/helm/v3 | Helm is not used by the agent - no helm packages in dependencies |
| GHSA-m425-mq94-257g | HIGH | helm | Same as above - Helm not included |
| CVE-2025-21613 | CRITICAL | moby/buildkit | BuildKit only used at build time, not in final image |
| CVE-2024-23653 | CRITICAL | moby/buildkit | Same as above |
| CVE-2024-23652 | CRITICAL | moby/buildkit | Same as above |
| CVE-2024-41110 | CRITICAL | moby: Authz | Agent doesn't use Docker/Moby - no Docker daemon in container |
| CVE-2025-46569 | HIGH | OPA server | Agent doesn't run OPA server - no OPA packages in go.mod |

### ⚠️ Base Image Issues (Alpine Only)

| CVE | Severity | Component | Mitigation |
|-----|----------|-----------|------------|
| CVE-2024-26147 | HIGH | musl libc (Alpine) | Use distroless image variant which uses glibc/Debian base |
| CVE-2024-25621 | HIGH | runc (Alpine) | Updated to Alpine 3.21 / Use distroless |
| CVE-2025-53547 | HIGH | containerd (Alpine) | Updated to Alpine 3.21 / Use distroless |

## Why Scanners Report False Positives

Vulnerability scanners can report false positives for several reasons:

1. **Build-time vs Runtime**: Tools like BuildKit are used during `docker build` but aren't in the final image
2. **Transitive scanning**: Scanners may look at the entire Docker build context, not just the final image
3. **Registry metadata**: Some registries cache vulnerability data incorrectly
4. **String matching**: Scanners may match package names without verifying actual presence

## Verification

### Verify packages are not in the image:

```bash
# Build the image
docker build -t prysm-agent:test -f Dockerfile .

# Check what's actually in the image
docker run --rm prysm-agent:test sh -c "find / -name '*helm*' 2>/dev/null" || echo "Not found"
docker run --rm prysm-agent:test sh -c "find / -name '*buildkit*' 2>/dev/null" || echo "Not found"
docker run --rm prysm-agent:test sh -c "find / -name '*opa*' 2>/dev/null" || echo "Not found"

# Check Go dependencies in the binary
docker run --rm prysm-agent:test ./prysm-agent --version 2>&1 | head -5
```

### Verify with Go tooling:

```bash
cd prysm-agent

# List all dependencies
go list -m all | grep -E "helm|opa|go-getter|buildkit|moby"
# Should return empty - these packages are not dependencies

# Check oauth2 version (should be v0.34.0 or later)
go list -m golang.org/x/oauth2
```

## Recommendations

### For Production Deployments:

1. **Use the distroless image variant** (eliminates musl/runc/containerd CVEs):
   ```bash
   helm install prysm-agent prysm/agent --set image.tag=distroless
   ```

2. **Configure scanner to ignore false positives**:
   - Create exceptions in your security policy for CVEs that are verified as not present
   - Focus on CVEs in packages that are actually in `go list -m all`

3. **Regular updates**:
   - Rebuild images monthly to get latest base image updates
   - Update Go dependencies quarterly
   - Monitor security advisories for k8s.io/* packages

### For Security Audits:

When auditors question these CVEs, provide:

1. **This document** explaining each CVE
2. **Dependency proof**: Output of `go list -m all` showing packages aren't included
3. **Runtime verification**: Output showing packages don't exist in running container
4. **Image comparison**: Show distroless variant has fewer CVEs

## Scanner-Specific Issues

### Trivy

Trivy sometimes reports build dependencies. To see only runtime dependencies:

```bash
trivy image --skip-dirs /var/lib/apt,/var/cache beehivesec/prysm-agent:latest
```

### Grype

Grype may cache old scan results. Clear cache:

```bash
grype db delete
grype db update
grype beehivesec/prysm-agent:latest
```

### Snyk

Snyk can scan both Dockerfile and final image. Ensure you're scanning the image, not the Dockerfile:

```bash
snyk container test beehivesec/prysm-agent:latest
```

## Contact

For security questions:
- Email: security@prysm.sh
- GitHub: https://github.com/prysmsh/prysm/security

For false positive verification:
- Open an issue with scanner output and we'll verify
- Provide: Scanner name, version, scan command, and full output
