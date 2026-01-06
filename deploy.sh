#!/bin/bash
set -e

echo "========================================================"
echo " SystemAPI.io - Deployment"
echo " Target: OCI Kubernetes (OKE)"
echo "========================================================"
echo ""

# Configuration - OCI Registry
OCI_REGION="${OCI_REGION:-us-ashburn-1}"
OCI_TENANCY="${OCI_TENANCY:-idd2oizp8xvc}"
OCIR_REPO="${OCI_REGION}.ocir.io/${OCI_TENANCY}/systemapi"
SERVICE_NAME="systemapi"
NAMESPACE="systemapi-prod"

# Get version from package.json or use timestamp
VERSION="${VERSION:-v1.0.0}"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
IMAGE_TAG="${VERSION}-${TIMESTAMP}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

MODE="${1:-help}"

case "$MODE" in
  build)
    echo -e "${YELLOW}Building Docker image...${NC}"
    docker build -t ${SERVICE_NAME}:latest -t ${SERVICE_NAME}:${IMAGE_TAG} .
    echo -e "${GREEN}Build complete: ${SERVICE_NAME}:${IMAGE_TAG}${NC}"
    ;;

  push)
    echo -e "${YELLOW}Tagging and pushing to OCI Registry...${NC}"

    # Tag for OCIR
    docker tag ${SERVICE_NAME}:latest ${OCIR_REPO}:latest
    docker tag ${SERVICE_NAME}:latest ${OCIR_REPO}:${IMAGE_TAG}

    # Push
    docker push ${OCIR_REPO}:latest
    docker push ${OCIR_REPO}:${IMAGE_TAG}

    echo -e "${GREEN}Pushed: ${OCIR_REPO}:${IMAGE_TAG}${NC}"
    ;;

  deploy)
    echo -e "${YELLOW}Full deployment: build -> push -> apply${NC}"

    # Build
    echo -e "${BLUE}Step 1: Building Docker image...${NC}"
    docker build -t ${SERVICE_NAME}:latest -t ${SERVICE_NAME}:${IMAGE_TAG} .

    # Tag
    echo -e "${BLUE}Step 2: Tagging for OCIR...${NC}"
    docker tag ${SERVICE_NAME}:latest ${OCIR_REPO}:latest
    docker tag ${SERVICE_NAME}:latest ${OCIR_REPO}:${IMAGE_TAG}

    # Push
    echo -e "${BLUE}Step 3: Pushing to OCI Registry...${NC}"
    docker push ${OCIR_REPO}:latest
    docker push ${OCIR_REPO}:${IMAGE_TAG}

    # Apply k8s manifests
    echo -e "${BLUE}Step 4: Applying Kubernetes manifests...${NC}"
    kubectl apply -f kubernetes/deployment.yaml

    # Create registry secret if it doesn't exist
    kubectl get secret oci-registry -n ${NAMESPACE} 2>/dev/null || \
      kubectl get secret oci-registry -n login -o yaml | sed "s/namespace: login/namespace: ${NAMESPACE}/" | kubectl apply -f -

    # Update Kubernetes
    echo -e "${BLUE}Step 5: Updating Kubernetes deployment...${NC}"
    kubectl set image deployment/${SERVICE_NAME} ${SERVICE_NAME}=${OCIR_REPO}:${IMAGE_TAG} -n ${NAMESPACE}

    # Wait for rollout
    echo -e "${BLUE}Step 6: Waiting for rollout...${NC}"
    kubectl rollout status deployment/${SERVICE_NAME} -n ${NAMESPACE} --timeout=120s

    echo ""
    echo -e "${GREEN}========================================================"
    echo " Deployment Complete!"
    echo "========================================================${NC}"
    echo ""
    echo "Image: ${OCIR_REPO}:${IMAGE_TAG}"
    echo "Service URL: https://systemapi.io"
    ;;

  status)
    echo -e "${BLUE}Deployment Status:${NC}"
    kubectl get deployment ${SERVICE_NAME} -n ${NAMESPACE}
    echo ""
    echo -e "${BLUE}Pods:${NC}"
    kubectl get pods -n ${NAMESPACE} -l app=${SERVICE_NAME}
    echo ""
    echo -e "${BLUE}Service:${NC}"
    kubectl get svc ${SERVICE_NAME} -n ${NAMESPACE}
    ;;

  logs)
    echo -e "${BLUE}Streaming logs...${NC}"
    kubectl logs -f deployment/${SERVICE_NAME} -n ${NAMESPACE} --all-containers=true
    ;;

  apply)
    echo -e "${YELLOW}Applying Kubernetes manifests...${NC}"
    kubectl apply -f kubernetes/deployment.yaml
    ;;

  *)
    echo "SystemAPI.io - Deployment"
    echo ""
    echo "Usage: $0 {build|push|deploy|status|logs|apply}"
    ;;
esac
