#!/bin/bash

# Enhanced Docker Compose Integration Test Runner
# This script runs the complete integration test suite using Docker Compose

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.test.yml"
PROJECT_NAME="prysm-agent-integration-test"
LOG_DIR="./test-logs"
TIMEOUT_SECONDS=600

echo -e "${BLUE}🚀 Starting Enhanced Prysm Integration Tests${NC}"
echo "======================================================"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up test environment...${NC}"
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME down -v --remove-orphans >/dev/null 2>&1 || true
    docker system prune -f >/dev/null 2>&1 || true
}

# Trap cleanup on exit
trap cleanup EXIT

# Create log directory
mkdir -p $LOG_DIR

echo -e "${BLUE}📦 Building Docker images...${NC}"
docker build -f Dockerfile.derp-server -t kubeaccess/derp-server:test . || {
    echo -e "${RED}❌ Failed to build DERP server image${NC}"
    exit 1
}

docker build -f Dockerfile -t kubeaccess/prysm-agent:test . || {
    echo -e "${RED}❌ Failed to build Prysm K8s agent image${NC}"
    exit 1
}

docker build -f Dockerfile.saas-backend -t kubeaccess/saas-backend:test . || {
    echo -e "${RED}❌ Failed to build SaaS backend image${NC}"
    exit 1
}

docker build -f Dockerfile.ui -t kubeaccess/ui:test . || {
    echo -e "${RED}❌ Failed to build UI image${NC}"
    exit 1
}

echo -e "${GREEN}✅ Docker images built successfully${NC}"

echo -e "${BLUE}🏗️  Starting test infrastructure...${NC}"

# Start foundational services first
echo "Starting PostgreSQL and Redis..."
docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d postgres redis

# Wait for database services
echo "Waiting for database services to be healthy..."
timeout 60 bash -c "until docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps postgres | grep 'healthy'; do sleep 2; done" || {
    echo -e "${RED}❌ PostgreSQL failed to start${NC}"
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs postgres
    exit 1
}

timeout 60 bash -c "until docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps redis | grep 'healthy'; do sleep 2; done" || {
    echo -e "${RED}❌ Redis failed to start${NC}"
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs redis
    exit 1
}

echo -e "${GREEN}✅ Database services ready${NC}"

# Start K3s clusters
echo "Starting K3s clusters..."
docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d k3s-server-1 k3s-server-2 k3s-server-3

# Wait for K3s clusters with longer timeout
echo "Waiting for K3s clusters to be ready (this may take a few minutes)..."
for cluster in k3s-server-1 k3s-server-2 k3s-server-3; do
    echo "Waiting for $cluster..."
    timeout 180 bash -c "until docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps $cluster | grep 'healthy'; do sleep 5; done" || {
        echo -e "${RED}❌ $cluster failed to start${NC}"
        docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs $cluster
        exit 1
    }
done

echo -e "${GREEN}✅ K3s clusters ready${NC}"

# Start DERP servers
echo "Starting DERP servers..."
docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d derp-server-1 derp-server-2 derp-server-3

# Wait for DERP servers
echo "Waiting for DERP servers to be ready..."
for derp in derp-server-1 derp-server-2 derp-server-3; do
    echo "Waiting for $derp..."
    timeout 60 bash -c "until docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps $derp | grep 'healthy'; do sleep 3; done" || {
        echo -e "${RED}❌ $derp failed to start${NC}"
        docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs $derp
        exit 1
    }
done

echo -e "${GREEN}✅ DERP servers ready${NC}"

# Start SaaS backend
echo "Starting SaaS backend..."
docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d kubeaccess-saas-backend

# Wait for SaaS backend
echo "Waiting for SaaS backend to be ready..."
timeout 120 bash -c "until docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps kubeaccess-saas-backend | grep 'healthy'; do sleep 5; done" || {
    echo -e "${RED}❌ SaaS backend failed to start${NC}"
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs kubeaccess-saas-backend
    exit 1
}

echo -e "${GREEN}✅ SaaS backend ready${NC}"

# Provision test workloads
echo "Provisioning test workloads..."
docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up test-workload-provisioner || {
    echo -e "${YELLOW}⚠️  Test workload provisioning had issues (non-critical)${NC}"
}

# Start Prysm K8s agents
echo "Starting Prysm K8s agents..."
docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d prysm-agent-1 prysm-agent-2 prysm-agent-3

echo -e "${BLUE}⏳ Waiting for system stabilization...${NC}"
sleep 30

# Show infrastructure status
echo -e "${BLUE}📊 Infrastructure Status:${NC}"
docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps

echo -e "\n${BLUE}🧪 Running integration tests...${NC}"

# Test DERP servers
echo "Testing DERP servers..."
for port in 8443 8444 8445; do
    curl -k -f "https://localhost:$port/health" >/dev/null 2>&1 || {
        echo -e "${RED}❌ DERP server on port $port is not responding${NC}"
        exit 1
    }
done
echo -e "${GREEN}✅ DERP servers responding${NC}"

# Test SaaS backend API
echo "Testing SaaS backend API..."
for endpoint in health metrics api/v1/clusters api/v1/services api/v1/derp/status api/v1/derp/metrics api/v1/derp/peers; do
    curl -f "http://localhost:8080/$endpoint" >/dev/null 2>&1 || {
        echo -e "${RED}❌ SaaS backend endpoint /$endpoint is not responding${NC}"
        exit 1
    }
done
echo -e "${GREEN}✅ SaaS backend API responding${NC}"

# Test K3s clusters
echo "Testing K3s cluster connectivity..."
for port in 7443 7444 7445; do
    curl -k -f "https://localhost:$port/version" >/dev/null 2>&1 || {
        echo -e "${RED}❌ K3s cluster on port $port is not responding${NC}"
        exit 1
    }
done
echo -e "${GREEN}✅ K3s clusters responding${NC}"

# Run Go integration tests
echo "Running Go-based integration tests..."
go test -v -run "TestDockerComposeIntegration" -timeout=10m || {
    echo -e "${RED}❌ Docker Compose integration tests failed${NC}"
    
    # Collect logs on failure
    echo "Collecting logs for debugging..."
    mkdir -p $LOG_DIR
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs kubeaccess-saas-backend > $LOG_DIR/saas-backend.log
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs prysm-agent-1 > $LOG_DIR/prysm-agent-1.log
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs prysm-agent-2 > $LOG_DIR/prysm-agent-2.log
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs prysm-agent-3 > $LOG_DIR/prysm-agent-3.log
    
    echo -e "${YELLOW}📝 Logs saved to $LOG_DIR/${NC}"
    exit 1
}

echo -e "${GREEN}✅ Integration tests passed${NC}"

# Generate test report
echo -e "${BLUE}📊 Generating test report...${NC}"
cat > test-report.md << EOF
# Docker Compose Integration Test Results

## Test Summary
- **Status**: ✅ PASSED
- **Date**: $(date)
- **Duration**: Test completed successfully

## Infrastructure Status
\`\`\`
$(docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps)
\`\`\`

## API Health Check Results
- SaaS Backend Health: $(curl -s http://localhost:8080/health | jq -r '.status')
- Total API Requests: $(curl -s http://localhost:8080/metrics | jq '.total_requests')
- Database Connected: $(curl -s http://localhost:8080/metrics | jq '.database_connected')
- Redis Connected: $(curl -s http://localhost:8080/metrics | jq '.redis_connected')

## DERP Network Status
- Network Status: $(curl -s http://localhost:8080/api/v1/derp/status | jq -r '.network_status')
- Total Servers: $(curl -s http://localhost:8080/api/v1/derp/status | jq '.total_servers')
- Active Servers: $(curl -s http://localhost:8080/api/v1/derp/status | jq '.active_servers')

## Performance Metrics
\`\`\`json
$(curl -s http://localhost:8080/metrics | jq .)
\`\`\`
EOF

echo -e "${GREEN}📄 Test report generated: test-report.md${NC}"

echo -e "\n${GREEN}🎉 All integration tests completed successfully!${NC}"
echo -e "${BLUE}💡 To view the test report: cat test-report.md${NC}"
echo -e "${BLUE}💡 To view logs: ls -la $LOG_DIR/${NC}"
echo -e "${BLUE}💡 Infrastructure will be cleaned up automatically${NC}"
