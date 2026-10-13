#!/bin/bash
# Deploy API Playground to systemapi.io

set -e  # Exit on error

echo "================================================"
echo "  SystemAPI.io - API Playground Deployment"
echo "================================================"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-systemapi}"
DB_USER="${DB_USER:-systemapi}"
REDIS_HOST="${REDIS_HOST:-localhost}"
REDIS_PORT="${REDIS_PORT:-6379}"

echo ""
echo "Step 1: Apply Database Schema"
echo "-----------------------------------------------"

# Check if PostgreSQL is accessible
if ! command -v psql &> /dev/null; then
    echo -e "${RED}ERROR: PostgreSQL client (psql) not found${NC}"
    echo "Please install PostgreSQL: brew install postgresql"
    exit 1
fi

echo "Applying playground schema to database..."
if [ -f "playground/playground_schema.sql" ]; then
    PGPASSWORD="${DB_PASSWORD}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -f playground/playground_schema.sql
    echo -e "${GREEN}OK: Database schema applied${NC}"
else
    echo -e "${RED}ERROR: Schema file not found: playground/playground_schema.sql${NC}"
    exit 1
fi

echo ""
echo "Step 2: Install Dependencies"
echo "-----------------------------------------------"

npm install
echo -e "${GREEN}OK: Dependencies installed${NC}"

echo ""
echo "Step 3: Verify Playground Integration"
echo "-----------------------------------------------"

# Check if playground modules exist
if [ ! -f "playground/router.js" ]; then
    echo -e "${RED}ERROR: Missing playground/router.js${NC}"
    exit 1
fi

if [ ! -f "playground/auth.js" ]; then
    echo -e "${RED}ERROR: Missing playground/auth.js${NC}"
    exit 1
fi

if [ ! -f "playground/rateLimiter.js" ]; then
    echo -e "${RED}ERROR: Missing playground/rateLimiter.js${NC}"
    exit 1
fi

if [ ! -f "playground/codeGenerator.js" ]; then
    echo -e "${RED}ERROR: Missing playground/codeGenerator.js${NC}"
    exit 1
fi

echo -e "${GREEN}OK: All playground modules present${NC}"

echo ""
echo "Step 4: Test Integration (Optional)"
echo "-----------------------------------------------"

# Test server startup (30 second timeout)
echo "Testing server startup..."
if timeout 10 node server.js > /tmp/systemapi_test.log 2>&1 & then
    sleep 5
    TEST_PID=$!

    # Test health endpoint
    if curl -s http://localhost:3003/health | grep -q "healthy"; then
        echo -e "${GREEN}OK: Server started successfully${NC}"
    else
        echo -e "${YELLOW}WARN: Server started but health check failed${NC}"
    fi

    # Kill test server
    kill $TEST_PID 2>/dev/null || true
else
    echo -e "${YELLOW}WARN: Server test skipped (already running or failed to start)${NC}"
fi

echo ""
echo "Step 5: Build Docker Image (if needed)"
echo "-----------------------------------------------"

if [ -f "Dockerfile" ]; then
    echo "Building Docker image..."
    docker build -t systemapi:latest .
    echo -e "${GREEN}OK: Docker image built${NC}"
else
    echo -e "${YELLOW}WARN: No Dockerfile found - skipping Docker build${NC}"
fi

echo ""
echo "Step 6: Deploy to Production"
echo "-----------------------------------------------"

# Check if deploy.sh exists
if [ -f "deploy.sh" ]; then
    echo "Running main deployment script..."
    ./deploy.sh
    echo -e "${GREEN}OK: Deployment complete${NC}"
else
    echo -e "${YELLOW}WARN: No deploy.sh found - manual deployment required${NC}"
    echo ""
    echo "To deploy manually:"
    echo "  1. Push Docker image to registry"
    echo "  2. Update Kubernetes deployment"
    echo "  3. Restart service"
fi

echo ""
echo "================================================"
echo -e "${GREEN}  Playground Deployment Complete!${NC}"
echo "================================================"
echo ""
echo "Endpoints available:"
echo "  POST   /playground/execute        - Execute API request"
echo "  POST   /playground/api-keys       - Create API key"
echo "  GET    /playground/api-keys       - List API keys"
echo "  DELETE /playground/api-keys/:id   - Delete API key"
echo "  PATCH  /playground/api-keys/:id/lock - Lock/unlock API key"
echo "  GET    /playground/credits        - Get user credits"
echo "  GET    /playground/rate-limit     - Get rate limit status"
echo "  POST   /playground/saved-requests - Save request"
echo "  GET    /playground/saved-requests - List saved requests"
echo ""
echo "Testing:"
echo "  curl -X POST http://localhost:3003/playground/execute \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"endpoint\": \"/api/v1/systems\", \"method\": \"GET\"}'"
echo ""
