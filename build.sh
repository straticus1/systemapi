#!/bin/bash
# Build systemapi.io for AMD64 architecture
set -e

echo "========================================================"
echo " SystemAPI.io - AMD64 Build Script"
echo "========================================================"
echo ""

# Configuration
OCI_REGION="${OCI_REGION:-us-ashburn-1}"
OCI_TENANCY="${OCI_TENANCY:-idd2oizp8xvc}"
OCIR_REPO="${OCI_REGION}.ocir.io/${OCI_TENANCY}/systemapi"
SERVICE_NAME="systemapi"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
VERSION="${VERSION:-v1.0.0}"
IMAGE_TAG="${VERSION}-${TIMESTAMP}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Building Docker image for AMD64 architecture...${NC}"
echo "Image tag: ${IMAGE_TAG}"
echo ""

# Build for AMD64 platform
echo -e "${YELLOW}Step 1: Building for linux/amd64...${NC}"
docker buildx build \
  --platform linux/amd64 \
  -t ${SERVICE_NAME}:latest \
  -t ${SERVICE_NAME}:${IMAGE_TAG} \
  -t ${OCIR_REPO}:latest \
  -t ${OCIR_REPO}:${IMAGE_TAG} \
  --load \
  .

echo -e "${GREEN}OK: Build complete${NC}"
echo ""

echo -e "${BLUE}Step 2: Pushing to OCI Registry...${NC}"
docker push ${OCIR_REPO}:latest
docker push ${OCIR_REPO}:${IMAGE_TAG}

echo ""
echo -e "${GREEN}========================================================"
echo " Build Complete!"
echo "========================================================${NC}"
echo ""
echo "Image: ${OCIR_REPO}:${IMAGE_TAG}"
echo ""
echo "To deploy, run:"
echo "  kubectl set image deployment/${SERVICE_NAME} ${SERVICE_NAME}=${OCIR_REPO}:${IMAGE_TAG} -n systemapi-prod"
echo "  kubectl rollout status deployment/${SERVICE_NAME} -n systemapi-prod"
echo ""
