#!/bin/bash

# Script to populate Prysm SaaS Backend with test data

echo "🚀 Adding test data to Prysm SaaS Backend..."

# Wait for backend to be ready
echo "⏳ Waiting for backend to be ready..."
until curl -s http://localhost:8080/health > /dev/null; do
  echo "Waiting for backend..."
  sleep 2
done

echo "✅ Backend is ready!"

# Register Production Cluster
echo "📝 Registering Production Cluster..."
curl -s -X POST http://localhost:8080/api/v1/clusters/register \
  -H "Content-Type: application/json" \
  -d '{
    "cluster_id": "production-cluster",
    "cluster_name": "Production K8s Cluster",
    "agent_token": "prod-token-12345",
    "agent_type": "enhanced",
    "cluster_info": {
      "id": "production-cluster",
      "name": "Production K8s Cluster",
      "region": "us-east-1",
      "version": "v1.28.5",
      "provider": "aws",
      "node_count": 5,
      "service_count": 12,
      "pod_count": 45,
      "namespace_count": 8,
      "health": "healthy",
      "cpu_usage": 42.5,
      "memory_usage": 68.2,
      "storage_usage": 51.4,
      "network_throughput": 185.0
    },
    "derp_client_id": "derp-client-prod-001",
    "capabilities": ["service-discovery", "monitoring", "proxy"]
  }' | jq .

# Register Staging Cluster
echo "📝 Registering Staging Cluster..."
curl -s -X POST http://localhost:8080/api/v1/clusters/register \
  -H "Content-Type: application/json" \
  -d '{
    "cluster_id": "staging-cluster",
    "cluster_name": "Staging K8s Cluster",
    "agent_token": "staging-token-67890",
    "agent_type": "enhanced",
    "cluster_info": {
      "id": "staging-cluster",
      "name": "Staging K8s Cluster",
      "region": "us-west-2",
      "version": "v1.28.5",
      "provider": "aws",
      "node_count": 3,
      "service_count": 8,
      "pod_count": 24,
      "namespace_count": 5,
      "health": "healthy",
      "cpu_usage": 37.8,
      "memory_usage": 54.6,
      "storage_usage": 33.2,
      "network_throughput": 92.4
    },
    "derp_client_id": "derp-client-staging-002",
    "capabilities": ["service-discovery", "monitoring"]
  }' | jq .

# Register Development Cluster
echo "📝 Registering Development Cluster..."
curl -s -X POST http://localhost:8080/api/v1/clusters/register \
  -H "Content-Type: application/json" \
  -d '{
    "cluster_id": "development-cluster",
    "cluster_name": "Development K8s Cluster",
    "agent_token": "dev-token-abcde",
    "agent_type": "enhanced",
    "cluster_info": {
      "id": "development-cluster",
      "name": "Development K8s Cluster",
      "region": "eu-central-1",
      "version": "v1.28.5",
      "provider": "gcp",
      "node_count": 2,
      "service_count": 6,
      "pod_count": 15,
      "namespace_count": 3,
      "health": "healthy",
      "cpu_usage": 28.1,
      "memory_usage": 41.7,
      "storage_usage": 22.9,
      "network_throughput": 48.3
    },
    "derp_client_id": "derp-client-dev-003",
    "capabilities": ["service-discovery"]
  }' | jq .

# Add some test service discovery data
echo "📝 Adding service discovery data for Production Cluster..."
curl -s -X POST http://localhost:8080/api/v1/clusters/production-cluster/data \
  -H "Content-Type: application/json" \
  -d '{
    "cluster_info": {
      "id": "production-cluster",
      "name": "Production K8s Cluster",
      "region": "us-east-1",
      "version": "v1.28.5",
      "provider": "aws",
      "node_count": 5,
      "service_count": 12,
      "pod_count": 45,
      "namespace_count": 8,
      "health": "healthy",
      "cpu_usage": 42.5,
      "memory_usage": 68.2,
      "storage_usage": 51.4,
      "network_throughput": 185.0
    },
    "services": {
      "frontend-service": {
        "name": "frontend-service",
        "namespace": "default",
        "type": "LoadBalancer",
        "cluster_ip": "10.43.1.100",
        "external_ip": "52.123.45.67",
        "ports": [{"port": 80, "protocol": "TCP"}],
        "last_seen": "2025-10-16T20:10:00Z"
      },
      "api-service": {
        "name": "api-service",
        "namespace": "default",
        "type": "ClusterIP",
        "cluster_ip": "10.43.1.101",
        "ports": [{"port": 8080, "protocol": "TCP"}],
        "last_seen": "2025-10-16T20:10:00Z"
      },
      "database-service": {
        "name": "database-service",
        "namespace": "database",
        "type": "ClusterIP",
        "cluster_ip": "10.43.2.50",
        "ports": [{"port": 5432, "protocol": "TCP"}],
        "last_seen": "2025-10-16T20:10:00Z"
      }
    }
  }' | jq .

echo "✅ Test data added successfully!"
echo ""
echo "🌟 Your Prysm UI should now have data!"
echo "   • UI: http://localhost:3000"
echo "   • Backend: http://localhost:8080"
echo "   • Clusters: $(curl -s http://localhost:8080/api/v1/clusters | jq '.total') registered"
echo ""
