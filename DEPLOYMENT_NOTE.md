# SystemAPI.io Deployment - Important Note

## Current Status: ✅ Stable (v1.0.0 running)

### Deployment Issue: Architecture Mismatch

The playground integration code is **complete and ready**, but cannot be deployed from this macOS ARM64 machine.

**Problem**: Docker on ARM64 Mac builds ARM64 images even with `--platform linux/amd64` flag. The Kubernetes cluster requires AMD64 architecture.

**Error**: `exec /usr/local/bin/docker-entrypoint.sh: exec format error`

---

## Solution: Deploy from Linux/AMD64 Environment

### Option 1: GitHub Actions / CI/CD (Recommended)

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy SystemAPI

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest  # AMD64 architecture

    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Login to OCI Registry
        run: |
          echo "${{ secrets.OCI_AUTH_TOKEN }}" | docker login us-ashburn-1.ocir.io \
            -u idd2oizp8xvc/coleman.ryan@gmail.com --password-stdin

      - name: Build and Push
        run: ./build.sh

      - name: Deploy to Kubernetes
        run: |
          echo "${{ secrets.KUBECONFIG }}" | base64 -d > /tmp/kubeconfig
          export KUBECONFIG=/tmp/kubeconfig
          ./deploy.sh deploy
```

### Option 2: Linux Server / VM

SSH into a Linux AMD64 server:

```bash
# Clone repo
git clone https://github.com/your-org/systemapi.io.git
cd systemapi.io

# Login to OCI Registry
echo "YOUR_AUTH_TOKEN" | docker login us-ashburn-1.ocir.io \
  -u idd2oizp8xvc/coleman.ryan@gmail.com --password-stdin

# Build and deploy
./build.sh
./deploy.sh deploy
```

### Option 3: Cloud Shell (OCI)

Use OCI Cloud Shell (already AMD64 and authenticated):

```bash
# Clone and deploy
git clone ...
cd systemapi.io
./build.sh
./deploy.sh deploy
```

---

## What's Ready to Deploy

All playground code is complete:

✅ **Backend Modules** (4 files):
- `playground/router.js` - All endpoints (execute, API keys, credits, etc.)
- `playground/auth.js` - Keycloak JWT + API key authentication
- `playground/rateLimiter.js` - Redis + PostgreSQL hybrid rate limiting
- `playground/codeGenerator.js` - Multi-language code snippets

✅ **Infrastructure**:
- `playground/playground_schema.sql` - Complete database schema
- `kubernetes/deployment.yaml` - Updated with env vars (DB/Redis)
- `build.sh` - AMD64 build script
- `deploy.sh` - Kubernetes deployment script

✅ **Integration**:
- `server.js` - Playground integration (optional if DB_PASSWORD not set)
- Dependencies installed (bcryptjs, jsonwebtoken, pg, redis, axios)

---

## Quick Deploy (from Linux AMD64)

```bash
cd /path/to/systemapi.io

# 1. Build AMD64 image
./build.sh

# 2. Deploy to Kubernetes
./deploy.sh deploy

# 3. Verify
kubectl get pods -n systemapi-prod
curl https://systemapi.io/health
```

---

## Current Deployment

**Version**: v1.0.0 (stable, without playground)
**Pods**: 2/2 running
**Status**: Healthy
**URL**: https://systemapi.io

**Playground Status**: Code complete, awaiting AMD64 deployment

---

## When Playground is Deployed

The playground will be available at:
- `POST /playground/execute` - Execute API requests
- `GET /playground/rate-limit` - Check rate limits
- `POST /playground/api-keys` - Create API keys
- `GET /playground/credits` - Check user credits

**Prerequisites** (configure in `kubernetes/deployment.yaml`):
- PostgreSQL database (shared or dedicated)
- Redis instance (shared or dedicated)
- Apply schema: `psql -f playground/playground_schema.sql`

---

## Files Modified

Created:
- `/playground/router.js` (17.2 KB)
- `/playground/auth.js` (7.4 KB)
- `/playground/rateLimiter.js` (10.1 KB)
- `/playground/codeGenerator.js` (6.2 KB)
- `/playground/playground_schema.sql` (10.0 KB)
- `/build.sh` - AMD64 build script
- `/deploy_playground.sh` - Deployment automation
- `/DEPLOYMENT_NOTE.md` - This file

Modified:
- `/server.js` - Added playground integration (optional based on DB_PASSWORD)
- `/kubernetes/deployment.yaml` - Added DB/Redis environment variables
- `/package.json` - Added dependencies

---

**Last Updated**: 2026-01-06
**Status**: Ready for Linux/AMD64 deployment
**Contact**: support@afterdarksys.com
