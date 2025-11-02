#!/usr/bin/env bash
set -euo pipefail

# Simplified script to always generate a fresh minikube "servers" profile and deploy
# required addons and components. This version is intentionally destructive and
# removes local OpenBao/Vault cached crypto and any previous minikube profile
# so it always starts clean.
#
# Notes:
# - Adjust PROTODIR to your project location if needed.
# - This script will remove PROTODIR/openbao/gen/crypto and /csr and recreate them.
# - metallb is configured non-interactively with a default address pool
#   based on the minikube IP (x.y.z.20-x.y.z.30).
# - Keep resource sizes tuned to your machine.

CLUSTER="servers"
PROTODIR=/media/tim/ExtraDrive1/Projects/009-SecureKeyAndCertRotation/deploy
CERT_MANAGER_VERSION="v1.17.3"

echo "=== Starting fresh deployment for minikube profile: $CLUSTER ==="

# Always delete previous profile
echo "-> Deleting existing minikube profile (if any)..."
minikube delete -p "$CLUSTER" || true

# Remove local generated crypto and csr to ensure fresh generation
#echo "-> Removing local PROTODIR caches (if present) and recreating directories..."
#rm -rf "$PROTODIR/openbao/gen/crypto" "$PROTODIR/openbao/gen/csr" || true
#mkdir -p "$PROTODIR/openbao/gen/crypto" "$PROTODIR/openbao/gen/csr"

# Start a fresh minikube profile
echo "-> Starting minikube profile $CLUSTER..."
minikube start -p "$CLUSTER" --cpus 3 --memory 12288 --vm-driver docker --cni kindnet --disk-size 100g

# Configure docker-env so subsequent docker commands (if any) use minikube's docker
eval "$(minikube -p "$CLUSTER" docker-env)"

# Enable useful addons
echo "-> Enabling minikube addons: dashboard, metallb..."
minikube -p "$CLUSTER" addons enable dashboard
minikube -p "$CLUSTER" addons enable metallb

# Configure loadbalancer ip address range within the same range as the minikube ip
# The configuration is a start ip ( ie. 192.168.49.20 ) and an end ip that makes a 
# range of 10 ip addresses. The range should not overlap the minikube ip
minikube -p $CLUSTER ip
minikube addons configure -p $CLUSTER metallb

# Start dashboard
minikube -p $CLUSTER dashboard &

# Install Kubernetes Gateway API CRDs (stable/experimental release)
echo "-> Installing Gateway API CRDs..."
kubectl --context="$CLUSTER" apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/experimental-install.yaml || true

# Try to wait a short time for CRDs to be established (best-effort)
echo "-> Waiting briefly for Gateway API CRDs to register..."
kubectl --context="$CLUSTER" wait --for=condition=established crd/gateways.gateway.networking.k8s.io --timeout=60s >/dev/null 2>&1 || true

# Install Istio in ambient mode with Gateway API enabled
echo "-> Installing Istio (ambient profile) with Gateway API enabled..."
istioctl --context="$CLUSTER" install --set values.pilot.env.PILOT_ENABLE_ALPHA_GATEWAY_API=true --set profile=ambient --skip-confirmation || true

# Create cert-manager namespace
kubectl --context="$CLUSTER" create namespace cert-manager --dry-run=client -o yaml | kubectl --context="$CLUSTER" apply -f -

# Apply cert-manager CRDs (required)
kubectl --context="$CLUSTER" apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.crds.yaml" || true


helm install cert-manager jetstack/cert-manager \
  --kube-context "$CLUSTER" \
  --namespace cert-manager \
  --create-namespace \
  --version "${CERT_MANAGER_VERSION}" \
  --set installCRDs=false \
  --set extraArgs[0]="--feature-gates=ExperimentalGatewayAPISupport=true" \
  --set config.enableGatewayAPI=true  

# Create pulsar namespace (fresh)
echo "-> Creating nats namespace..."
kubectl --context="$CLUSTER" create namespace nats --dry-run=client -o yaml | kubectl --context="$CLUSTER" apply -f -

echo "=== Minikube profile '$CLUSTER' is ready with dashboard, metallb, Gateway API CRDs, Istio (ambient), and cert-manager installed. ==="

