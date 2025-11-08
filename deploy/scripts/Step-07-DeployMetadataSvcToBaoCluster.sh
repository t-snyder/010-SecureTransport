#!/bin/bash

##########################################################################################
# Refactored Step-07 to use explicit YAML files
# Metadata service with NATS JetStream and simple mTLS authorization
##########################################################################################

set -e  # Exit on error

# Prompt for local host IP if not set -- Used for NATS connection
if [[ -z "$HOST_IP" ]]; then
  read -p "Enter the local host IP accessible from minikube (e.g., 10.1.1.12): " HOST_IP
fi

# Project directory path - change as needed
PROTODIR=${PROTODIR:-/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy}
SCHEMADIR=${SCHEMADIR:-/media/tim/ExtraDrive1/Projects/010-SecureTransport/svc-core/src/main/resources/avro}
DEPLOYDIR="$PROTODIR/kube-metadata"
NAMESPACE="metadata"
CA_CERT_PATH="/openbao/userconfig/openbao-tls/openbao.ca"

# Minikube profiles
MINIKUBE_BAO_PROFILE="bao"

echo "============================================================================="
echo "Starting Metadata Service Deployment"
echo "============================================================================="

##########################################################################################
# Get Vault Role ID and Secret ID
##########################################################################################
echo ""
echo "Step 1: Setting up OpenBao authentication..."
minikube profile $MINIKUBE_BAO_PROFILE

kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

ROLE_ID=$(kubectl exec -i -n openbao openbao-0 -- bao read -ca-cert=$CA_CERT_PATH -field=role_id auth/approle/role/metadata/role-id | tr -d '\r\n')
if [ -z "$ROLE_ID" ]; then
    echo "ERROR: Failed to retrieve ROLE_ID"
    exit 1
fi

SECRET_ID=$(kubectl exec -i -n openbao openbao-0 -- bao write -ca-cert=$CA_CERT_PATH -field=secret_id -f auth/approle/role/metadata/secret-id | tr -d '\r\n')
if [ -z "$SECRET_ID" ]; then
    echo "ERROR: Failed to retrieve SECRET_ID"
    exit 1
fi

echo "✓ Retrieved OpenBao credentials"
echo "  Role ID: ${ROLE_ID:0:20}..."
echo "  Secret ID: ${SECRET_ID:0:20}..."

##########################################################################################
# Create Kubernetes secrets
##########################################################################################
echo ""
echo "Step 2: Creating Kubernetes secrets..."

# Create Kubernetes secrets for OpenBao AppRole
kubectl create secret generic metadata-bao-approle \
        --from-literal=role-id="$ROLE_ID" \
        --from-literal=secret-id="$SECRET_ID" \
        --namespace=$NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
echo "✓ Created metadata-bao-approle secret"

# Create NATS CA secret (using same nats_int intermediate CA)
NATS_CA="$PROTODIR/openbao/gen/crypto/nats_ca_bundle.pem"
if [ ! -f "$NATS_CA" ]; then
    echo "ERROR: NATS CA file not found at $NATS_CA"
    exit 1
fi
kubectl create secret generic nats-ca-secret \
        --from-file=ca.crt="$NATS_CA" \
        --namespace=$NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
echo "✓ Created nats-ca-secret"

# Create OpenBao CA secret
BAO_CLIENT_CA_BUNDLE="$PROTODIR/openbao/gen/crypto/openbao.ca"
if [ ! -f "$BAO_CLIENT_CA_BUNDLE" ]; then
    echo "ERROR: OpenBao CA file not found at $BAO_CLIENT_CA_BUNDLE"
    exit 1
fi
kubectl create secret generic openbao-ca-secret \
        --from-file=ca.crt="$BAO_CLIENT_CA_BUNDLE" \
        --namespace=$NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
echo "✓ Created openbao-ca-secret"

##########################################################################################
# Generate templated YAML files with variables
##########################################################################################
echo ""
echo "Step 3: Generating templated configuration files..."

HOST_IP=$(hostname -I | cut -f1 -d' ')
BAO_ADDR="https://openbao.openbao.svc.cluster.local:8200"
BAO_CA_BUNDLE_B64=$(base64 -w0 < "$BAO_CLIENT_CA_BUNDLE")

# Generate metadata-tls-issuer.yaml - now saved to file
cat > "$DEPLOYDIR/metadata-tls-issuer.yaml" <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: metadata-tls-issuer
  namespace: $NAMESPACE
spec:
  vault:
    path: nats_int/sign/metadata-tls-issuer
    server: $BAO_ADDR
    caBundle: $BAO_CA_BUNDLE_B64
    auth:
      appRole:
        path: approle
        roleId: $ROLE_ID
        secretRef:
          name: metadata-bao-approle
          key: secret-id
EOF
echo "✓ Generated metadata-tls-issuer.yaml"

# Create metadata configuration for NATS
NATS_URL="tls://$HOST_IP:4222"

cat > "$DEPLOYDIR/metadata-configmap.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: metadata-configmap
  namespace: $NAMESPACE
data:
  messaging.url: "$NATS_URL"
  messaging.type: "nats"
  messaging.tls.enabled: "true"
  messaging.tls.cert: "/etc/nats-client-tls-certs/tls.crt"
  messaging.tls.key: "/etc/nats-client-tls-certs/tls.key"
  messaging.tls.ca: "/etc/nats-ca-certs/ca.crt"
  messaging.client.identity: "metadata"
  messaging.service.id: "metadata"
EOF
echo "✓ Generated metadata-configmap.yaml"

##########################################################################################
# Build the metadata-svc microservice image
##########################################################################################
echo ""
echo "Step 4: Building metadata-svc Docker image..."
if [ -f "$PROTODIR/scripts/buildMetadataImage.sh" ]; then
    /bin/bash $PROTODIR/scripts/buildMetadataImage.sh
    echo "✓ Built metadata-svc image"
else
    echo "WARNING: buildMetadataImage.sh not found at $PROTODIR/scripts/buildMetadataImage.sh"
fi

##########################################################################################
# Create avro-schemas configmap
##########################################################################################
echo ""
echo "Step 5: Creating avro-schemas configmap..."
if [ -d "$SCHEMADIR" ]; then
    kubectl create -n metadata configmap avro-schemas \
      --from-file=$SCHEMADIR/ \
      --dry-run=client -o yaml | kubectl apply -f -
    echo "✓ Created avro-schemas configmap"
else
    echo "WARNING: Schema directory not found at $SCHEMADIR"
fi

##########################################################################################
# Apply all YAML files in order
##########################################################################################
echo ""
echo "Step 6: Deploying Kubernetes resources..."

# 1. Service Account and RBAC
echo "  → Applying Service Account and RBAC..."
kubectl apply -n metadata -f $DEPLOYDIR/metadata-sa.yaml
kubectl apply -n metadata -f $DEPLOYDIR/metadata-rbac.yaml

# 2. PersistentVolumeClaims
echo "  → Applying PersistentVolumeClaims..."
kubectl apply -n metadata -f $DEPLOYDIR/metadata-pvc.yaml

# 3. ConfigMaps
echo "  → Applying ConfigMaps..."
kubectl apply -n metadata -f $DEPLOYDIR/bao-agent-configmap.yaml

kubectl create configmap metadata-configmap \
  --from-file=$PROTODIR/kube-metadata/metadataConfig.json \
  --dry-run=client -o yaml | kubectl apply -n metadata -f -

# Check if services-acl-configmap.yaml exists before applying
if [ -f "$DEPLOYDIR/services-acl-configmap.yaml" ]; then
    kubectl apply -n metadata -f $DEPLOYDIR/services-acl-configmap.yaml
    echo "  → Applied services-acl-configmap"
fi

# 4. Certificate Issuer
echo "  → Applying Certificate Issuer..."
kubectl apply -n metadata -f $DEPLOYDIR/metadata-tls-issuer.yaml

# Wait for issuer to be ready
echo "  → Waiting for issuer to be ready..."
sleep 5
if ! kubectl wait --for=condition=ready issuer/metadata-tls-issuer -n $NAMESPACE --timeout=60s 2>/dev/null; then
    echo "  WARNING: Issuer readiness check timed out, continuing anyway..."
    kubectl describe issuer -n $NAMESPACE metadata-tls-issuer
fi

# 5. Certificate Request
echo "  → Requesting NATS client certificate..."
kubectl apply -n metadata -f $DEPLOYDIR/metadata-nats-certificate.yaml

# Wait for certificate to be ready with better error handling
echo "  → Waiting for certificate to be issued (this may take up to 5 minutes)..."
if ! kubectl wait --for=condition=ready certificate/metadata-nats-client-tls -n $NAMESPACE --timeout=300s; then
    echo ""
    echo "ERROR: Certificate failed to be issued within timeout."
    echo ""
    echo "=== Certificate Status ==="
    kubectl get certificate -n $NAMESPACE metadata-nats-client-tls -o yaml
    echo ""
    echo "=== Certificate Request Status ==="
    kubectl get certificaterequest -n $NAMESPACE
    echo ""
    echo "=== Issuer Status ==="
    kubectl get issuer -n $NAMESPACE metadata-tls-issuer -o yaml
    echo ""
    echo "=== cert-manager logs (last 50 lines) ==="
    kubectl logs -n cert-manager -l app=cert-manager --tail=50
    exit 1
fi

# Verify the secret was created
if ! kubectl get secret -n $NAMESPACE metadata-nats-client-tls &>/dev/null; then
    echo "ERROR: Certificate secret 'metadata-nats-client-tls' was not created"
    kubectl get secrets -n $NAMESPACE
    exit 1
fi
echo "✓ Certificate issued and secret created successfully"

# 6. Deploy metadata service
echo "  → Deploying metadata service..."
kubectl apply -n metadata -f $DEPLOYDIR/metadata-deployment.yaml

# 7. Create service
echo "  → Creating metadata-service..."
kubectl apply -n metadata -f $DEPLOYDIR/metadata-service.yaml

##########################################################################################
# Set namespaces as part of the istio ambient mesh
##########################################################################################
echo ""
echo "Step 7: Configuring Istio ambient mesh..."
kubectl label namespace metadata istio.io/dataplane-mode=ambient --overwrite
kubectl label namespace openbao istio.io/dataplane-mode=ambient --overwrite
echo "✓ Namespaces configured for Istio ambient mesh"

##########################################################################################
# Display deployment status
##########################################################################################
echo ""
echo "Step 9: Deployment Status"
echo "============================================================================="
kubectl get pods -n $NAMESPACE -l app=metadata
echo ""
kubectl get svc -n $NAMESPACE metadata-service
echo ""
kubectl get certificate -n $NAMESPACE metadata-nats-client-tls

##########################################################################################
# Final instructions
##########################################################################################
echo ""
echo "============================================================================="
echo "Deployment Complete!"
echo "============================================================================="
