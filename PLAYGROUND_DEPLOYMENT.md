# API Playground Deployment for systemapi.io

## Status: Ready for Implementation

The API Playground infrastructure has been prepared for systemapi.io. This document guides you through the deployment.

## What's Included

1. **playground/** - Express.js playground module
   - `codeGenerator.js` - Code snippet generation
   - `README.md` - Full documentation
   - `package.json` - Dependencies

2. **playground_schema.sql** - Database schema for PostgreSQL

## Implementation Steps

### Step 1: Install Dependencies

```bash
cd /Users/ryan/development/systemapi.io
npm install express bcryptjs jsonwebtoken pg redis axios
```

### Step 2: Apply Database Schema

If systemapi.io uses PostgreSQL, apply the schema:

```bash
# Replace with your database credentials
psql -h localhost -U systemapi_user -d systemapi_db -f playground_schema.sql
```

If systemapi.io doesn't have PostgreSQL yet:

```bash
# Install PostgreSQL
brew install postgresql

# Create database
createdb systemapi_db
psql systemapi_db -f playground_schema.sql
```

### Step 3: Set up Redis

```bash
# Install Redis
brew install redis

# Start Redis
redis-server
```

### Step 4: Implement Full Playground Router

Due to the complexity, reference implementations are available in:
- **Flask version**: `/Users/ryan/development/api-playground-flask/`
- **FastAPI version**: `/Users/ryan/development/api-playground-fastapi/`
- **Go version**: `/Users/ryan/development/api-playground-go/`

Key components needed:
1. `playground/router.js` - Express router with all endpoints
2. `playground/auth.js` - Authentication middleware
3. `playground/rateLimiter.js` - Rate limiting logic

### Step 5: Integrate into server.js

Add the following to `server.js`:

```javascript
// After existing middleware setup, around line 35:

// Database connection (if using PostgreSQL)
const { Pool } = require('pg');
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'systemapi',
  user: process.env.DB_USER || 'systemapi',
  password: process.env.DB_PASSWORD
});

// Redis connection
const { createClient } = require('redis');
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379'
});
redisClient.connect().then(() => {
  console.log('✓ Redis connected');
}).catch(err => {
  console.error('⚠ Redis connection failed:', err.message);
});

// Playground setup
try {
  const CodeSnippetGenerator = require('./playground/codeGenerator');
  const codeGenerator = new CodeSnippetGenerator(
    process.env.API_BASE_URL || 'https://api.systemapi.io',
    'systemapi'
  );

  // TODO: Implement full playground router
  // For now, add a basic endpoint
  app.post('/playground/execute', async (req, res) => {
    const { endpoint, method = 'GET', headers = {}, query_params = {}, body = null } = req.body;

    // Generate code snippets
    const codeSnippets = codeGenerator.generateAll(endpoint, method, headers, query_params, body);

    res.json({
      success: true,
      message: 'Playground endpoint (implementation in progress)',
      code_snippets: codeSnippets
    });
  });

  console.log('✓ API Playground initialized at /playground');
} catch (err) {
  console.error('⚠ Playground initialization failed:', err.message);
}
```

### Step 6: Update package.json

Ensure dependencies are listed:

```json
{
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "compression": "^1.7.4",
    "morgan": "^1.10.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "pg": "^8.11.3",
    "redis": "^4.6.12",
    "axios": "^1.6.5"
  }
}
```

### Step 7: Deploy

```bash
# Test locally
npm install
node server.js

# Deploy to production
./deploy.sh
```

## Alternative: Use Existing Database (DarkAPI/AfterDark)

If systemapi.io doesn't need its own database, you can connect to the shared AfterDark/DarkAPI PostgreSQL instance:

```javascript
const pool = new Pool({
  host: 'shared-db-host',
  port: 5432,
  database: 'afterdark_shared',
  user: 'systemapi',
  password: process.env.SHARED_DB_PASSWORD
});
```

## Testing

Once deployed, test the playground:

```bash
curl -X POST https://api.systemapi.io/playground/execute \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint": "/api/v1/systems",
    "method": "GET"
  }'
```

## Full Implementation Reference

For complete implementation with all features (rate limiting, API keys, saved requests), refer to:

### Flask Implementation (nerdapi.io, darkapi.io)
- `/Users/ryan/development/nerdapi.io/playground/`
- `/Users/ryan/development/darkapi.io/api/playground/`

### FastAPI Implementation (planetapi.ai, nextapi.io)
- `/Users/ryan/development/api-playground-fastapi/`

### Go Implementation (computeapi.io)
- `/Users/ryan/development/computeapi.io/internal/playground/`

## Next Steps

1. ✅ Database schema prepared
2. ✅ Code generator implemented
3. ⏳ Implement full Express router (router.js, auth.js, rateLimiter.js)
4. ⏳ Integrate into server.js
5. ⏳ Deploy and test

## Support

For questions or assistance:
- Review completed implementations in Flask/FastAPI/Go
- Check `/Users/ryan/development/API-PLAYGROUND-IMPLEMENTATION.md`
- Contact: support@afterdarksys.com

---

**Status**: Scaffolding complete, ready for full implementation
**Last Updated**: 2026-01-06
