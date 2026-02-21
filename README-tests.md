# Test Suite Documentation

This document describes the comprehensive test suite for the P2P DERP Network and Kubernetes Agent integration.

## Test Overview

Our comprehensive test suite provides complete coverage of the P2P DERP network and Kubernetes agent functionality using **real infrastructure** instead of mocks. The tests run against actual Docker Compose stacks with real K3s clusters, DERP servers, and the production SaaS backend.

### Test Categories

1. **Unit Tests** - Test individual components in isolation
2. **Integration Tests** - Test against real Docker Compose stack with K3s clusters
3. **Real Performance Tests** - Performance testing with actual clusters and workloads  
4. **Benchmarks** - Micro-benchmarks using real infrastructure
5. **End-to-End Tests** - Complete SaaS platform workflows with real services

## Test Files Structure

```
├── p2p_derp_server_test.go         # Unit tests for P2P DERP server
├── derp_federation_test.go         # Unit tests for server federation  
├── k8s_agent_test.go               # Unit tests for Prysm K8s agent
├── integration_tests.go            # Integration tests with real K3s clusters
├── real_performance_test.go        # Performance tests with real infrastructure
├── test/
│   ├── integration_test_framework.go  # Test framework for real clusters
│   ├── run-integration-tests.sh       # Test runner script
│   ├── kubeaccess-saas-backend.go     # Production SaaS backend
│   └── k8s-manifests/                 # Real Kubernetes workloads
├── docker-compose.test.yml         # Complete test infrastructure
└── .github/workflows/test-suite.yml # CI/CD pipeline
```

## Running Tests

### Prerequisites

```bash
# Install Go 1.21+
go version

# Set the organization identifier used for DERP isolation features
export ORGANIZATION_ID=1

# Install development dependencies
make dev-setup

# Download project dependencies
make deps
```

### Quick Test Run

```bash
# Run all tests (unit + integration with real clusters)
make test

# Run specific test categories
make test-unit                    # Unit tests only
make test-integration            # Integration tests with real K3s clusters
make test-performance           # Performance tests with real infrastructure  
make test-benchmarks           # Benchmarks with real clusters

# Integration test management
make test-integration-setup     # Setup test environment only
make test-integration-cleanup   # Cleanup test environment
make test-integration-verbose   # Run with verbose output

# Direct script usage
./test/run-integration-tests.sh                    # Run all integration tests
./test/run-integration-tests.sh -v                 # Verbose output
./test/run-integration-tests.sh TestIntegration_*  # Specific test pattern
./test/run-integration-tests.sh --setup-only       # Setup only
```

### Individual Test Commands

```bash
# Unit tests for DERP server
go test -v -run "TestP2PDERPServer"

# Integration tests for federation
go test -v -run "TestDERPFederation"

# Prysm K8s agent tests
go test -v -run "TestEnhancedK8sAgent"

# End-to-end tests
go test -v -run "TestE2E"

# Performance benchmarks
go test -bench=.
```

## Test Categories Detailed

### 1. Unit Tests (`*_test.go`)

#### P2P DERP Server Tests (`p2p_derp_server_test.go`)

Tests core DERP server functionality:

- **TestP2PDERPServer_NewServer** - Server initialization
- **TestP2PDERPServer_ClientRegistration** - Client registration flow
- **TestP2PDERPServer_MessageRelay** - Message routing between clients
- **TestP2PDERPServer_Discovery** - Peer discovery mechanism
- **TestP2PDERPServer_Heartbeat** - Health monitoring
- **TestP2PDERPServer_HTTPEndpoints** - REST API endpoints
- **TestP2PDERPServer_ErrorHandling** - Error scenarios

```bash
# Run DERP server unit tests
go test -v -run "TestP2PDERPServer" -coverprofile=derp-coverage.out
```

#### Prysm K8s Agent Tests (`k8s_agent_test.go`)

Tests Kubernetes agent functionality:

- **TestEnhancedK8sAgent_NewAgent** - Agent initialization
- **TestEnhancedK8sAgent_ServiceDiscovery** - Kubernetes service discovery
- **TestEnhancedK8sAgent_ClusterInfo** - Cluster metadata collection
- **TestEnhancedK8sAgent_DERPMessageHandling** - DERP message processing
- **TestEnhancedK8sAgent_HealthCheckHandling** - Health check responses
- **TestEnhancedK8sAgent_ResourceAccessHandling** - Resource access requests

```bash
# Run Prysm K8s agent unit tests
go test -v -run "TestEnhancedK8sAgent" -coverprofile=k8s-coverage.out
```

### 2. Integration Tests (`derp_federation_test.go`)

Tests multi-server federation:

- **TestDERPFederation_TwoServerNetwork** - Basic server-to-server connection
- **TestDERPFederation_ThreeServerMesh** - Multi-server mesh formation
- **TestDERPFederation_CrossServerClientDiscovery** - Cross-server client discovery
- **TestDERPFederation_CrossServerMessageRelay** - Cross-server message routing
- **TestDERPFederation_ServerHealthMonitoring** - Server health monitoring
- **TestDERPFederation_LoadBalancing** - Client distribution across servers

```bash
# Run federation integration tests
go test -v -run "TestDERPFederation" -timeout=10m
```

### 3. End-to-End Tests (`e2e_saas_integration_test.go`)

Tests complete SaaS workflows:

- **TestE2E_FullSaaSWorkflow** - Complete SaaS platform simulation
- **TestE2E_CrossClusterCommunication** - Multi-cluster communication
- **TestE2E_AgentFailureRecovery** - Fault tolerance testing
- **TestE2E_ServiceDiscoveryAccuracy** - Service discovery validation

```bash
# Run E2E tests
go test -v -run "TestE2E" -timeout=15m
```

### 4. Performance Tests (`performance_test.go`)

Tests scalability and performance:

#### Load Tests
- **TestDERPServer_LoadTest** - Concurrent client load testing
- **TestDERPServer_MemoryUsage** - Memory usage under load
- **TestK8sAgent_ConcurrentDiscovery** - Concurrent service discovery
- **TestFederation_ScalabilityTest** - Multi-server scalability

#### Benchmarks
- **BenchmarkDERPServer_ClientConnections** - Connection establishment speed
- **BenchmarkDERPServer_MessageThroughput** - Message routing performance
- **BenchmarkK8sAgent_ServiceDiscovery** - Service discovery performance

```bash
# Run performance tests
make test-performance

# Run specific benchmarks
go test -bench="BenchmarkDERPServer.*" -benchmem
```

## Test Environment Setup

### Mock Kubernetes Environment

Tests use a comprehensive mock kubectl environment:

```go
// Example mock setup
func createMockKubernetesEnvironment(tmpDir string) error {
    kubectlScript := filepath.Join(tmpDir, "kubectl")
    kubectlContent := `#!/bin/bash
    case "$*" in
        "get services --all-namespaces -o json")
            echo '{"items": [...]}'  # Mock service data
            ;;
        "get nodes --no-headers")
            echo "master-1 Ready"
            ;;
    esac`
    
    return ioutil.WriteFile(kubectlScript, []byte(kubectlContent), 0755)
}
```

### Test Data

Tests use realistic mock data:

- **Services**: Multiple service types (ClusterIP, LoadBalancer, NodePort)
- **Endpoints**: Pod IP addresses and port mappings
- **Cluster Info**: Version, provider, node counts
- **DERP Messages**: Registration, discovery, relay, heartbeat

## CI/CD Pipeline

### GitHub Actions Workflow

The test suite runs automatically on:

- **Push to main/develop** - Full test suite
- **Pull Requests** - Full test suite with PR comments
- **Scheduled** - Daily performance tests
- **Manual** - On-demand test execution

### Pipeline Stages

1. **Code Quality**
   - Go formatting check
   - Linting with golangci-lint
   - Security scanning with gosec
   - Vulnerability checking with govulncheck

2. **Unit Tests**
   - Parallel execution by test suite
   - Coverage reporting to Codecov
   - Test result artifacts

3. **Integration Tests**
   - DERP federation testing
   - Multi-server scenarios
   - Cross-component integration

4. **End-to-End Tests**
   - Complete SaaS workflow simulation
   - Multi-cluster scenarios
   - Failure recovery testing

5. **Performance Tests**
   - Load testing with concurrent clients
   - Benchmark execution
   - Performance regression detection

6. **Security Tests**
   - Static analysis security scanning
   - Dependency vulnerability scanning
   - Container security scanning

7. **Kubernetes Integration**
   - k3s cluster deployment
   - Manifest validation
   - Pod deployment testing

### Build and Deploy

- **Docker Images**: Multi-stage builds for DERP server and Prysm K8s agent
- **Container Registry**: Push to GitHub Container Registry
- **Deployment**: Staging environment deployment on main branch

## Test Configuration

### Environment Variables

Tests use environment variables for configuration:

```bash
export CLUSTER_ID="test-cluster"
export REGION="test-region" 
export DERP_SERVERS="wss://test-derp1.com/derp,wss://test-derp2.com/derp"
export AGENT_TOKEN="test-token"
export BACKEND_URL="https://test-backend.com"
```

### Test Flags

Common test execution flags:

```bash
# Verbose output
go test -v

# Race condition detection
go test -race

# Coverage reporting
go test -coverprofile=coverage.out

# Timeout for long tests
go test -timeout=15m

# Benchmark memory allocations
go test -bench=. -benchmem

# Run specific test pattern
go test -run="TestE2E.*"
```

## Test Metrics and Reporting

### Coverage Goals

- **Unit Tests**: >85% code coverage
- **Integration Tests**: >70% component interaction coverage
- **E2E Tests**: >90% user workflow coverage

### Performance Benchmarks

Target performance metrics:

- **DERP Server**: >1000 req/sec message throughput
- **Prysm K8s Agent**: <100ms service discovery latency
- **Federation**: <5s mesh formation time
- **Memory Usage**: <100MB per 1000 clients

### Test Results

Test results are available through:

- **GitHub Actions**: Workflow run details
- **Codecov**: Coverage reports and trends
- **Artifacts**: Detailed test logs and results
- **PR Comments**: Automated test result summaries

## Debugging Failed Tests

### Common Issues

1. **Timing Issues**
   ```bash
   # Increase timeouts for slow environments
   go test -timeout=30m
   ```

2. **Port Conflicts**
   ```bash
   # Check for conflicting processes
   netstat -an | grep 8443
   ```

3. **Mock Setup**
   ```bash
   # Verify mock kubectl is in PATH
   which kubectl
   ```

### Debug Flags

```bash
# Enable debug logging
go test -v -args -debug

# Keep test artifacts
go test -v -args -keep-artifacts

# Single test execution
go test -v -run="TestSpecificTest" -count=1
```

### Test Isolation

Each test uses isolated environments:

- Temporary directories for mock scripts
- Unique port assignments
- Independent test clients
- Cleanup functions for resource management

## Contributing to Tests

### Adding New Tests

1. Follow naming conventions: `Test<Component>_<Feature>`
2. Use table-driven tests for multiple scenarios
3. Include both positive and negative test cases
4. Add benchmarks for performance-critical code

### Test Best Practices

1. **Isolation**: Tests should not depend on each other
2. **Determinism**: Tests should produce consistent results
3. **Speed**: Unit tests should complete quickly (<1s)
4. **Clarity**: Test names should describe what they test
5. **Coverage**: Test both happy path and error conditions

### Example Test Structure

```go
func TestComponent_Feature(t *testing.T) {
    // Setup
    setup := createTestEnvironment()
    defer setup.Cleanup()
    
    // Test cases
    testCases := []struct {
        name     string
        input    interface{}
        expected interface{}
        wantErr  bool
    }{
        {"valid input", validInput, expectedOutput, false},
        {"invalid input", invalidInput, nil, true},
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Execute
            result, err := componentMethod(tc.input)
            
            // Assert
            if tc.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tc.expected, result)
            }
        })
    }
}
```

This comprehensive test suite ensures the reliability, performance, and security of the P2P DERP network and Kubernetes agent integration, providing confidence for production deployments.
