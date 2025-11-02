#!/bin/bash

# Step 02 - Deploy OpenBao (Vault fork) with TLS enabled on Kubernetes
# - Creates cert-manager issuers and certificates
# - Waits for TLS secrets
# - Patches the openbao-tls secret with expected key names
# - Deploys OpenBao using Helm or manifests with 3 replicas/raft HA

set -e

# --- Configuration ---
export SERVICE_NAME=openbao-internal
export NAMESPACE=openbao
export SECRET_NAME=openbao-tls
export PROTODIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy

# Create directories if they do not exist
mkdir -p $PROTODIR/openbao/gen/crypto
mkdir -p $PROTODIR/openbao/gen/csr

# -- 1. Select Kubernetes context (if using minikube profile for openbao) --
minikube profile bao

# -- 2. Create Namespace for OpenBao (if not already) --
kubectl apply -n openbao -f $PROTODIR/openbao/kube/openbao-namespace.yaml

# -- 3. Create cert-manager issuers and certificates for OpenBao --
kubectl apply -n openbao -f $PROTODIR/openbao/kube/openbao-issuer.yaml

# Wait for CA secret to exist
while true; do
    if kubectl get secret openbao-ca-secret -n openbao > /dev/null 2>&1; then
        echo "Secret openbao-ca-secret exists."
        break
    else
        echo "Waiting for secret openbao-ca-secret to be created..."
        sleep 5
    fi
done

kubectl apply -n openbao -f $PROTODIR/openbao/kube/openbao-certs.yaml
# Wait for TLS secret to exist
while true; do
    if kubectl get secret openbao-tls -n openbao > /dev/null 2>&1; then
        echo "Secret openbao-tls exists."
        break
    else
        echo "Waiting for secret openbao-tls to be created..."
        sleep 5
    fi
done

# -- 4. Save CA cert to disk (optional, for inspection/troubleshooting) --
kubectl get secret openbao-ca-secret -n openbao -o jsonpath='{.data.ca\.crt}' | base64 -d > ${PROTODIR}/openbao/gen/crypto/openbao.ca

# -- 5. Patch openbao-tls secret with expected key names for OpenBao --
CA_CERT=$(kubectl get secret openbao-ca-secret -n $NAMESPACE -o jsonpath='{.data.ca\.crt}')
TLS_KEY=$(kubectl get secret openbao-tls -n openbao -o jsonpath='{.data.tls\.key}')
TLS_CRT=$(kubectl get secret openbao-tls -n openbao -o jsonpath='{.data.tls\.crt}')

kubectl patch secret openbao-tls -n openbao --type='json' -p="[
  {\"op\": \"add\", \"path\": \"/data/openbao.key\", \"value\": \"${TLS_KEY}\"},
  {\"op\": \"add\", \"path\": \"/data/openbao.crt\", \"value\": \"${TLS_CRT}\"},
  {\"op\": \"add\", \"path\": \"/data/openbao.ca\",  \"value\": \"${CA_CERT}\"}
]"

# -- 6. Verify the openbao-tls secret contains all required keys --
kubectl get secret openbao-tls -n openbao -o yaml

# Install the OpenBao
#helm repo add openbao https://openbao.github.io/openbao-helm
#helm repo update

# -- 7. Deploy OpenBao manifests (StatefulSet, ConfigMap, Services, etc.) --
helm install openbao openbao/openbao -n openbao -f ${PROTODIR}/openbao/kube/openbao-values-tls.yaml

echo "OpenBao deployment initiated. Wait for pods to be ready, then proceed to initialize/unseal the cluster."
