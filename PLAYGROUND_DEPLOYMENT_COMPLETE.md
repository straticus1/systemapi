# SystemAPI.io - API Playground Deployment Complete

## Status: ✅ Ready for Production Deployment

The API Playground has been successfully implemented and integrated into systemapi.io.

## What Was Implemented

### Core Modules
1. **playground/router.js** - Express router with all endpoints
   - `/playground/execute` - Execute API requests
   - `/playground/api-keys` - Full API key management (CRUD)
   - `/playground/credits` - User credit tracking
   - `/playground/rate-limit` - Rate limit status
   - `/playground/saved-requests` - Save and manage requests

2. **playground/auth.js** - Authentication manager
   - Keycloak JWT token verification
   - API key generation and verification
   - Bcrypt-based key hashing
   - IP whitelisting support
   - Endpoint restrictions

3. **playground/rateLimiter.js** - Hybrid rate limiting
   - Redis for fast checks
   - PostgreSQL fallback
   - Automatic daily/monthly resets
   - Usage tracking and analytics

4. **playground/codeGenerator.js** - Multi-language code snippets
   - Python (requests)
   - Go (net/http)
   - Node.js (axios)
   - PHP (cURL)
   - cURL commands

5. **playground/playground_schema.sql** - Complete database schema
   - `playground_api_keys` - API key management
   - `playground_credits` - User credits and tiers
   - `playground_usage` - Request tracking
   - `anonymous_rate_limits` - Anonymous user tracking
   - `playground_tiers` - Tier configuration
   - `saved_requests` - Saved request templates

### Integration
- **server.js** - Fully integrated with Express app
- **kubernetes/deployment.yaml** - Updated with DB/Redis environment variables
- **deploy_playground.sh** - Automated deployment script

## Rate Limiting Tiers

| Tier | Daily Limit | Monthly Limit | Features |
|------|-------------|---------------|----------|
| Anonymous | 50 | - | Basic testing |
| Free | 100 | 3,000 | Code snippets, API explorer |
| Starter | 1,000 | 30,000 | + Saved requests |
| Professional | 10,000 | 300,000 | + Team sharing |
| Enterprise | 100,000 | - | Unlimited features |

## Dependencies Installed

```json
{
  "bcryptjs": "^2.4.3",      // Password hashing for API keys
  "jsonwebtoken": "^9.0.2",  // JWT verification
  "pg": "^8.11.3",           // PostgreSQL client
  "redis": "^4.6.12",        // Redis client
  "axios": "^1.6.5",         // HTTP client for proxying
  "uuid": "^9.0.0"           // Request ID generation
}
```

## Database Setup Required

### Option 1: Shared Database (Recommended)
Use the AfterDark shared PostgreSQL instance (Neon or OCI):

```bash
# Connect to shared database
PGPASSWORD='<shared_password>' psql \
  -h <shared-host> \
  -p 5432 \
  -U systemapi \
  -d afterdark_shared \
  -f playground/playground_schema.sql
```

Update `kubernetes/deployment.yaml`:
```yaml
- name: DB_HOST
  value: "<shared-postgres-host>"
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: systemapi-secrets
      key: db-password
```

### Option 2: Dedicated Database
Create a dedicated PostgreSQL database for systemapi.io:

```bash
# Create database
createdb systemapi

# Apply schema
psql -U systemapi -d systemapi -f playground/playground_schema.sql
```

## Redis Setup Required

### Option 1: Shared Redis (Recommended)
Use the AfterDark shared Redis instance:

Update `kubernetes/deployment.yaml`:
```yaml
- name: REDIS_URL
  value: "redis://<shared-redis-host>:6379"
```

### Option 2: Deploy Redis to Kubernetes
```bash
# Deploy Redis to systemapi-prod namespace
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: systemapi-prod
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: systemapi-prod
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
EOF
```

## Deployment Steps

### 1. Configure Database and Redis
Update the TODOs in `kubernetes/deployment.yaml`:
- Set `DB_HOST` to actual PostgreSQL host
- Set `REDIS_URL` to actual Redis URL
- Create `db-password` secret in Kubernetes

### 2. Apply Database Schema
```bash
# Run the schema file against your database
PGPASSWORD='<password>' psql \
  -h <db-host> \
  -U systemapi \
  -d systemapi \
  -f playground/playground_schema.sql
```

### 3. Create Kubernetes Secrets
```bash
# Create database password secret
kubectl create secret generic systemapi-secrets \
  --from-literal=db-password='<your-db-password>' \
  --from-literal=jwt-secret='afterdark-entertainment-systems-2024' \
  -n systemapi-prod
```

### 4. Deploy to Production
```bash
# Run the automated deployment
./deploy_playground.sh

# Or use the main deploy script
./deploy.sh deploy
```

### 5. Verify Deployment
```bash
# Check deployment status
./deploy.sh status

# Check logs
./deploy.sh logs

# Test playground endpoint
curl -X POST https://api.systemapi.io/playground/execute \
  -H 'Content-Type: application/json' \
  -d '{
    "endpoint": "/api/v1/systems",
    "method": "GET"
  }'
```

## API Endpoints

### Playground Execution
```bash
POST /playground/execute
```
Execute an API request and get code snippets.

**Request:**
```json
{
  "endpoint": "/api/v1/systems",
  "method": "GET",
  "headers": {"Authorization": "Bearer token"},
  "query_params": {"page": 1},
  "body": null
}
```

**Response:**
```json
{
  "success": true,
  "status_code": 200,
  "response_data": {...},
  "response_time_ms": 45,
  "request_id": "uuid",
  "code_snippets": {
    "python": "import requests...",
    "go": "package main...",
    "node": "const axios = require('axios')...",
    "php": "<?php...",
    "curl": "curl -X GET..."
  },
  "usage": {
    "daily_used": 5,
    "daily_limit": 100,
    "remaining": 95
  }
}
```

### API Key Management
```bash
# Create API key (requires authentication)
POST /playground/api-keys
{
  "name": "My API Key",
  "description": "For testing",
  "expires_in_days": 365
}

# List API keys
GET /playground/api-keys

# Delete API key
DELETE /playground/api-keys/:keyId

# Lock/unlock API key
PATCH /playground/api-keys/:keyId/lock
{
  "locked": true
}
```

### Credits & Usage
```bash
# Get user credits
GET /playground/credits

# Get rate limit status
GET /playground/rate-limit
```

### Saved Requests
```bash
# Save a request
POST /playground/saved-requests
{
  "name": "List Systems",
  "endpoint": "/api/v1/systems",
  "method": "GET"
}

# List saved requests
GET /playground/saved-requests?folder=testing
```

## Security Features

1. **API Key Security**
   - Bcrypt hashing (10 rounds)
   - Format: `ak_live_{16chars}.{32char_secret}`
   - One-time display on creation
   - IP whitelisting support
   - Endpoint restrictions

2. **Rate Limiting**
   - Anonymous: 50 requests/day (by IP)
   - Authenticated: Based on tier (100-100,000/day)
   - Redis-backed with PostgreSQL fallback
   - Automatic daily resets

3. **Authentication**
   - Keycloak JWT tokens
   - API key authentication
   - Optional dual-auth support

## Testing Locally

```bash
# Start local PostgreSQL and Redis
brew services start postgresql
brew services start redis

# Create local database
createdb systemapi
psql systemapi -f playground/playground_schema.sql

# Set environment variables
export DB_HOST=localhost
export DB_NAME=systemapi
export DB_USER=$USER
export REDIS_URL=redis://localhost:6379

# Start server
npm install
node server.js
```

Test endpoints:
```bash
# Test anonymous execution
curl -X POST http://localhost:3003/playground/execute \
  -H 'Content-Type: application/json' \
  -d '{"endpoint": "/api/v1/systems", "method": "GET"}'

# Test rate limit status
curl http://localhost:3003/playground/rate-limit
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  systemapi.io                       │
│                  (Express.js)                       │
└───────────────────┬─────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        │   /playground router  │
        └───────────┬───────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
   ┌────▼────┐          ┌───────▼──────┐
   │  Auth   │          │ Rate Limiter │
   │ Manager │          │              │
   └────┬────┘          └───────┬──────┘
        │                       │
        │                  ┌────▼─────┐
        │                  │  Redis   │
        │                  │ (Cache)  │
        │                  └──────────┘
        │
   ┌────▼─────────────────────────┐
   │     PostgreSQL Database      │
   │  - playground_api_keys       │
   │  - playground_credits        │
   │  - playground_usage          │
   │  - anonymous_rate_limits     │
   │  - saved_requests            │
   └──────────────────────────────┘
```

## Next Steps

1. **Configure Production Database**
   - Decide: shared database or dedicated instance
   - Apply schema
   - Update Kubernetes secrets

2. **Configure Redis**
   - Decide: shared Redis or dedicated instance
   - Update Kubernetes deployment

3. **Deploy to Production**
   - Run `./deploy.sh deploy`
   - Verify endpoints
   - Monitor logs

4. **Optional: Frontend Integration**
   - Create React playground UI component
   - Deploy to systemapi.io website
   - Connect to playground API

## Support

For questions or issues:
- Review implementation in other API sites:
  - nerdapi.io (Flask)
  - darkapi.io (Flask)
  - computeapi.io (Go)
  - planetapi.ai (FastAPI)
- Check `/Users/ryan/development/API-PLAYGROUND-IMPLEMENTATION.md`
- Contact: support@afterdarksys.com

---

**Status**: ✅ Implementation Complete - Ready for Database/Redis Configuration and Deployment
**Last Updated**: 2026-01-06
