# API Playground for Express.js

A comprehensive API playground module for Express.js applications with rate limiting, API key management, and code snippet generation.

## Features

- **Interactive API Testing**: Test endpoints with custom headers, query parameters, and request bodies
- **Rate Limiting**: Redis + PostgreSQL hybrid rate limiting
  - Anonymous users: 50 requests/day
  - Free tier: 100 requests/day
  - Tiered credits for paid plans
- **Authentication**: Keycloak/JWT token + API key management
- **Code Generation**: Automatic code snippets in Python, Go, Node.js, PHP, and cURL

## Installation

```bash
npm install
```

## Dependencies

- express: ^4.18.2
- bcryptjs: ^2.4.3 (for API key hashing)
- jsonwebtoken: ^9.0.2 (for JWT verification)
- pg: ^8.11.3 (PostgreSQL client)
- redis: ^4.6.12 (Redis client)
- axios: ^1.6.5 (HTTP client for proxying requests)

## Database Setup

Apply the database schema:

```bash
psql -U your_user -d your_db -f playground_schema.sql
```

## Integration Example

```javascript
const express = require('express');
const { createClient } = require('redis');
const { Pool } = require('pg');
const playgroundRouter = require('./playground');

const app = express();

// Database connection
const pool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'systemapi',
  user: 'systemapi',
  password: process.env.DB_PASSWORD
});

// Redis connection
const redisClient = createClient({
  url: 'redis://localhost:6379'
});
redisClient.connect();

// Initialize playground
const playgroundConfig = {
  db: pool,
  redis: redisClient,
  keycloakURL: 'https://aftercloak.io',
  keycloakRealm: 'afterdark',
  keycloakClientID: 'systemapi',
  apiSite: 'systemapi',
  baseURL: 'https://api.systemapi.io'
};

// Register playground routes
app.use('/playground', playgroundRouter(playgroundConfig));

app.listen(3000, () => {
  console.log('✓ API Playground initialized at /playground');
});
```

## API Endpoints

### Execute Playground Request
`POST /playground/execute`

**Request:**
```json
{
  "endpoint": "/api/v1/users",
  "method": "GET",
  "headers": {"Authorization": "Bearer token"},
  "query_params": {"page": 1},
  "body": null
}
```

### API Key Management
- `POST /playground/api-keys` - Create new API key (auth required)
- `GET /playground/api-keys` - List user's API keys (auth required)
- `DELETE /playground/api-keys/:keyId` - Delete API key (auth required)
- `PATCH /playground/api-keys/:keyId/lock` - Lock/unlock API key (auth required)

### Usage & Credits
- `GET /playground/credits` - Get user's credit info (auth required)
- `GET /playground/rate-limit` - Get current rate limit status

## Implementation for systemapi.io

The complete implementation includes:

1. **router.js** - Express router with all endpoints
2. **auth.js** - Authentication middleware (Keycloak + API keys)
3. **rateLimiter.js** - Rate limiting logic (Redis + PostgreSQL)
4. **codeGenerator.js** - Code snippet generation (all languages)
5. **playground_schema.sql** - Database schema

Due to the complexity, a simplified version is provided. For full implementation, refer to the Flask or FastAPI versions and adapt to Express.js patterns.

## Quick Start for systemapi.io

1. Copy this module to systemapi.io:
```bash
cp -r playground /path/to/systemapi.io/
```

2. Install dependencies:
```bash
cd /path/to/systemapi.io
npm install express bcryptjs jsonwebtoken pg redis axios
```

3. Apply database schema:
```bash
psql -U systemapi -d systemapi_db -f playground_schema.sql
```

4. Add to your Express app (see Integration Example above)

## Rate Limit Tiers

| Tier | Daily Limit | Cost |
|------|-------------|------|
| Anonymous | 50 | Free |
| Free Account | 100 | Free |
| Starter | 1,000 | $9.99/mo |
| Professional | 10,000 | $29.99/mo |
| Enterprise | 100,000 | $99.99/mo |

## Security

- API keys are hashed with bcrypt before storage
- JWT tokens are verified against Keycloak JWKS (configure in production)
- IP whitelisting supported for API keys
- Endpoint restrictions supported for API keys

## License

Copyright © 2026 AfterDark Systems. All rights reserved.
