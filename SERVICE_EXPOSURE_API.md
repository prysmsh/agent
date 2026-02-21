# Service Exposure API Documentation

## Overview

The Service Exposure API provides a comprehensive solution for exposing Kubernetes services discovered by the kubeaccess agent through a secure, configurable network gateway. This SaaS feature allows users to:

- **Configure service exposure** with granular access controls
- **Manage authentication** with token-based access
- **Control traffic** with rate limiting and CORS policies
- **Monitor usage** with comprehensive analytics
- **Secure access** through DERP network tunneling

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User/Client   │────│  Exposure API    │────│  DERP Network   │
│                 │    │   (Backend)      │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                │                        │
                       ┌──────────────────┐    ┌─────────────────┐
                       │   Configuration  │    │  Prysm K8s Agent      │
                       │    Database      │    │  (In Cluster)   │
                       └──────────────────┘    └─────────────────┘
                                                        │
                                                ┌─────────────────┐
                                                │ Kubernetes API  │
                                                │   Services      │
                                                └─────────────────┘
```

## API Endpoints

### Service Exposure Management

#### 1. Expose/Configure Service
```http
PUT /api/v1/services/{cluster_id}/{namespace}/{service_name}/expose
```

**Request Body:**
```json
{
  "is_exposed": true,
  "exposure_type": "http",              // "http", "tcp", "udp"
  "external_port": 8080,                // optional
  "custom_domain": "api.example.com",   // optional
  "auth_required": true,
  "rate_limit_rpm": 1000,               // requests per minute
  "allowed_origins": ["https://app.com", "https://localhost:3000"],
  "metadata": {
    "description": "Public API service",
    "owner": "backend-team",
    "tags": ["production", "public"]
  }
}
```

**Response:**
```json
{
  "status": "configured",
  "cluster_id": "prod-cluster-1",
  "service_name": "api-service",
  "namespace": "default",
  "is_exposed": true,
  "external_url": "https://api.example.com",
  "service_info": {
    "name": "api-service",
    "type": "ClusterIP",
    "ports": [{"port": 8080, "protocol": "TCP"}]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### 2. Get Service Exposure Configuration
```http
GET /api/v1/services/{cluster_id}/{namespace}/{service_name}/config
```

**Response:**
```json
{
  "id": 1,
  "cluster_id": "prod-cluster-1",
  "service_name": "api-service",
  "namespace": "default",
  "is_exposed": true,
  "exposure_type": "http",
  "external_port": 8080,
  "custom_domain": "api.example.com",
  "auth_required": true,
  "rate_limit_rpm": 1000,
  "allowed_origins": ["https://app.com"],
  "metadata": {"owner": "backend-team"},
  "created_at": "2024-01-15T10:00:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

#### 3. List Exposed Services
```http
GET /api/v1/clusters/{cluster_id}/exposed-services
```

**Response:**
```json
{
  "cluster_id": "prod-cluster-1",
  "exposed_services": [
    {
      "id": 1,
      "service_name": "api-service",
      "namespace": "default",
      "is_exposed": true,
      "exposure_type": "http",
      "external_port": 8080,
      "auth_required": true,
      "rate_limit_rpm": 1000
    }
  ],
  "total": 1,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### 4. Bulk Expose Services
```http
PUT /api/v1/clusters/{cluster_id}/bulk-expose
```

**Request Body:**
```json
{
  "services": [
    {
      "service_name": "frontend-service",
      "namespace": "default",
      "is_exposed": true,
      "exposure_type": "http"
    },
    {
      "service_name": "internal-api",
      "namespace": "backend",
      "is_exposed": false
    }
  ]
}
```

### Access Token Management

#### 5. Create Access Token
```http
POST /api/v1/services/{cluster_id}/{namespace}/{service_name}/access-token
```

**Request Body:**
```json
{
  "user_id": "user-123",
  "permissions": ["read", "write", "exec"],
  "expires_in": 3600  // seconds
}
```

**Response:**
```json
{
  "access_token": "sat_prod-cluster-1_default_api-service_1642248600",
  "cluster_id": "prod-cluster-1",
  "service_name": "api-service",
  "namespace": "default",
  "user_id": "user-123",
  "permissions": ["read", "write"],
  "expires_at": "2024-01-15T11:30:00Z",
  "expires_in": 3600,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Public Service Access

#### 6. Access Exposed Service
```http
GET|POST|PUT|DELETE /api/v1/exposed/{cluster_id}/{namespace}/{service_name}[/{path}]
```

**Headers:**
```
Authorization: Bearer sat_prod-cluster-1_default_api-service_1642248600
Origin: https://app.example.com
```

**Example:**
```bash
curl -H "Authorization: Bearer sat_..." \
     -H "Origin: https://app.example.com" \
     https://api.kubeaccess.com/api/v1/exposed/prod-cluster-1/default/api-service/users
```

## Security Features

### 1. Authentication

- **Token-based access**: Bearer tokens for API access
- **User identification**: Track access by user ID
- **Permission-based**: Granular permissions (read, write, exec)
- **Token expiration**: Configurable token lifetimes

### 2. Authorization

- **Service-level control**: Enable/disable exposure per service
- **Namespace isolation**: Services isolated by Kubernetes namespace
- **CORS protection**: Configurable allowed origins
- **Rate limiting**: Requests per minute limits

### 3. Network Security

- **DERP tunneling**: Secure P2P network tunneling to clusters
- **TLS encryption**: All traffic encrypted in transit
- **Origin validation**: CORS policy enforcement
- **Request logging**: Comprehensive audit trail

## Configuration Options

### Exposure Types

1. **HTTP/HTTPS** (`exposure_type: "http"`)
   - Web applications and REST APIs
   - Full HTTP method support (GET, POST, PUT, DELETE)
   - CORS and content-type handling

2. **TCP** (`exposure_type: "tcp"`)
   - Database connections
   - Custom protocols
   - Raw TCP traffic forwarding

3. **UDP** (`exposure_type: "udp"`)
   - DNS services
   - Real-time communications
   - Gaming protocols

### Rate Limiting

- **Per-minute limits**: Configure requests per minute per client IP
- **Sliding window**: Distributed rate limiting using Redis
- **Bypass for errors**: Rate limiting disabled if Redis is unavailable
- **Per-service configuration**: Individual limits per exposed service

### Custom Domains

- **CNAME support**: Point your domain to the exposure endpoint
- **SSL/TLS termination**: Automatic certificate management
- **Path-based routing**: Route based on URL paths
- **Port specification**: Custom port exposure

## Usage Examples

### Example 1: Expose a Web Application

```bash
# 1. Configure exposure
curl -X PUT "$API_BASE/services/my-cluster/default/webapp/expose" \
  -H "Content-Type: application/json" \
  -d '{
    "is_exposed": true,
    "exposure_type": "http",
    "custom_domain": "app.mycompany.com",
    "auth_required": false,
    "rate_limit_rpm": 2000,
    "allowed_origins": ["*"]
  }'

# 2. Access the application
curl https://app.mycompany.com/api/health
```

### Example 2: Secure API with Token Access

```bash
# 1. Configure secure exposure
curl -X PUT "$API_BASE/services/prod-cluster/api/backend-service/expose" \
  -H "Content-Type: application/json" \
  -d '{
    "is_exposed": true,
    "exposure_type": "http",
    "auth_required": true,
    "rate_limit_rpm": 500,
    "allowed_origins": ["https://admin.mycompany.com"]
  }'

# 2. Create access token
curl -X POST "$API_BASE/services/prod-cluster/api/backend-service/access-token" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "admin-user",
    "permissions": ["read", "write"],
    "expires_in": 86400
  }'

# 3. Access with token
curl -H "Authorization: Bearer <token>" \
     -H "Origin: https://admin.mycompany.com" \
     "$API_BASE/exposed/prod-cluster/api/backend-service/admin/users"
```

### Example 3: Database Access via TCP

```bash
# 1. Expose database service
curl -X PUT "$API_BASE/services/db-cluster/database/postgres/expose" \
  -H "Content-Type: application/json" \
  -d '{
    "is_exposed": true,
    "exposure_type": "tcp",
    "external_port": 5432,
    "auth_required": true,
    "rate_limit_rpm": 100
  }'

# 2. Create database access token
curl -X POST "$API_BASE/services/db-cluster/database/postgres/access-token" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "db-admin",
    "permissions": ["read", "write"],
    "expires_in": 3600
  }'
```

## Database Schema

### Service Exposure Configurations
```sql
CREATE TABLE service_exposure_configs (
    id SERIAL PRIMARY KEY,
    cluster_id VARCHAR(255) REFERENCES clusters(cluster_id),
    service_name VARCHAR(255) NOT NULL,
    namespace VARCHAR(255) NOT NULL,
    is_exposed BOOLEAN DEFAULT false,
    exposure_type VARCHAR(50) DEFAULT 'http',
    external_port INT,
    custom_domain VARCHAR(255),
    auth_required BOOLEAN DEFAULT true,
    rate_limit_rpm INT DEFAULT 1000,
    allowed_origins TEXT[],
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(cluster_id, service_name, namespace)
);
```

### Access Tokens
```sql
CREATE TABLE service_access_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    cluster_id VARCHAR(255),
    service_name VARCHAR(255),
    namespace VARCHAR(255),
    user_id VARCHAR(255),
    permissions TEXT[],
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## Error Handling

### Common Error Responses

#### Service Not Found (404)
```json
{
  "error": "Service not found",
  "cluster_id": "my-cluster",
  "service_name": "unknown-service",
  "namespace": "default"
}
```

#### Service Not Exposed (403)
```json
{
  "error": "Service not exposed",
  "message": "This service is not configured for external access"
}
```

#### Rate Limit Exceeded (429)
```json
{
  "error": "Rate limit exceeded",
  "limit": 1000,
  "window": "1 minute",
  "retry_after": 45
}
```

#### Invalid Token (401)
```json
{
  "error": "Unauthorized",
  "message": "Invalid or expired access token"
}
```

## Monitoring and Analytics

### Metrics Available

1. **Request Metrics**
   - Request count by service
   - Response times
   - Error rates
   - Status code distribution

2. **Traffic Analytics**
   - Bandwidth usage
   - Geographic distribution
   - Peak usage times
   - Client IP analysis

3. **Security Metrics**
   - Authentication failures
   - Rate limit violations
   - CORS policy violations
   - Token usage patterns

### Prometheus Metrics
```
# Request metrics
kubeaccess_exposed_service_requests_total{cluster_id, service_name, namespace, method, status_code}
kubeaccess_exposed_service_request_duration_seconds{cluster_id, service_name, namespace}

# Rate limiting
kubeaccess_rate_limit_violations_total{cluster_id, service_name, namespace}

# Authentication
kubeaccess_auth_failures_total{cluster_id, service_name, namespace, reason}
```

## Best Practices

### Security
1. **Enable authentication** for all production services
2. **Use restrictive CORS** policies instead of wildcard origins
3. **Set appropriate rate limits** based on service capacity
4. **Regular token rotation** for long-running applications
5. **Monitor access patterns** for anomaly detection

### Performance
1. **Configure rate limits** to protect backend services
2. **Use custom domains** for better performance and branding
3. **Enable caching** where appropriate
4. **Monitor response times** and adjust cluster resources

### Operations
1. **Use bulk operations** for managing multiple services
2. **Implement proper metadata** for service organization
3. **Regular cleanup** of expired tokens
4. **Monitor database growth** and implement retention policies

This comprehensive API enables secure, scalable service exposure for Kubernetes clusters with fine-grained control and monitoring capabilities.