#!/bin/bash
# Deploy Gatekeeper

set -euo pipefail

#-----------------------------
# Configurable Paths / Inputs
#-----------------------------
PROTODIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy
SCHEMADIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/svc-core/src/main/resources/avro
CA_CERT="/openbao/userconfig/openbao-tls/openbao.ca"
NATS_CA_SECRET_NAME="nats-ca-secret"

# Switch to new terminal for services cluster
minikube profile services

kubectl create namespace gatekeeper --dry-run=client -o yaml | kubectl apply -f -

#-----------------------------
# Avro Schemas ConfigMap
#-----------------------------
echo "[INFO] Creating avro-schemas ConfigMap"
kubectl create -n gatekeeper configmap avro-schemas \
  --from-file="${SCHEMADIR}/" \
  --dry-run=client -o yaml | kubectl apply -f -

#========================================
# OpenBao (Vault) Setup for Gatekeeper
#========================================
minikube profile bao

echo "Creating gatekeeper-tls-issuer role..."
kubectl exec -n openbao openbao-0 -i -- bao write -ca-cert="${CA_CERT}" nats_int/roles/gatekeeper-tls-issuer \
  allowed_domains=gatekeeper \
  allow_subdomains=true \
  allow_bare_domains=true \
  allow_any_name=true \
  max_ttl=12h \
  key_type=rsa \
  key_bits=4096

# Set the policy for the gatekeeper-issuer role
echo "Creating gatekeeper-tls-issuer policy..."
kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert="${CA_CERT}" gatekeeper-tls-issuer - <<EOF
path "nats_int/*"                           { capabilities = ["read", "list"] }
path "nats_int/roles/gatekeeper-tls-issuer" { capabilities = ["read", "list", "create", "update"] }
path "nats_int/sign/gatekeeper-tls-issuer"  { capabilities = ["create", "update"] }
path "nats_int/issue/gatekeeper-tls-issuer" { capabilities = ["create"] }
EOF

# Create a policy for the application
echo "Creating policy: gatekeeper-policy"
kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert="${CA_CERT}" gatekeeper-policy - <<EOF
# Allow reading secrets from specific path
path "secret/data/gatekeeper/*" {
  capabilities = ["read"]
}

# Allow token renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow token lookup
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow creating new secret-ids for the gatekeeper AppRole (required for secret-id rotation)
path "auth/approle/role/gatekeeper/secret-id" {
  capabilities = ["update", "create"]
}

# Allow access to CA bundle
path "nats_int/ca_chain" {
  capabilities = ["read"]
}

# Allow ServiceBundle read for gatekeeper
path "secret/data/service-bundles/gatekeeper/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/service-bundles/gatekeeper/*" {
  capabilities = ["read", "list"]
}

# Allow CaBundle read for NATS
path "secret/data/ca-bundles/NATS/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/ca-bundles/NATS/*" {
  capabilities = ["read", "list"]
}

# Also allow reading metadata service bundles (for verification keys)
path "secret/data/service-bundles/metadata/*" {
  capabilities = ["read", "list"]
}
EOF

# Create AppRole for gatekeeper
echo "Creating AppRole: gatekeeper"
kubectl exec -n openbao openbao-0 -i -- bao write -ca-cert="${CA_CERT}" auth/approle/role/gatekeeper \
    token_policies="gatekeeper-policy,gatekeeper-tls-issuer,signing-keys-read,gatekeeper-signing-keys-write" \
    token_ttl=1d \
    token_max_ttl=1d \
    bind_secret_id=true \
    secret_id_ttl=12h \
    secret_id_num_uses=0

ROLE_ID=$(kubectl exec -i -n openbao openbao-0 -- bao read -ca-cert="${CA_CERT}" -field=role_id auth/approle/role/gatekeeper/role-id | tr -d '\r\n')
if [ -z "$ROLE_ID" ]; then
    echo "Failed to retrieve ROLE_ID"
    exit 1
fi

SECRET_ID=$(kubectl exec -i -n openbao openbao-0 -- vault write -ca-cert="${CA_CERT}" -field=secret_id -f auth/approle/role/gatekeeper/secret-id | tr -d '\r\n')
if [ -z "$SECRET_ID" ]; then
    echo "Failed to retrieve SECRET_ID"
    exit 1
fi

echo "Role ID: $ROLE_ID"
echo "Secret ID: $SECRET_ID"

# Use the cleaned variables to get the token
#BAO_TOKEN=$(kubectl exec -i -n openbao openbao-0 -- sh << EOF
#bao write -field=token auth/approle/login \
#    role_id="$ROLE_ID" \
#    secret_id="$SECRET_ID"
#EOF
#)

# Completed vault setup for the gatekeeper service
###########################################################################################

# Switch minikube profile back to servers
minikube profile services

# Create Kubernetes secrets
kubectl create secret generic gatekeeper-bao-approle \
        --from-literal=role-id="$ROLE_ID" \
        --from-literal=secret-id="$SECRET_ID" \
        --namespace=gatekeeper \
        --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic "${NATS_CA_SECRET_NAME}" \
        --from-file=ca.crt="$PROTODIR/openbao/gen/crypto/nats_ca.crt" \
        --namespace=gatekeeper --dry-run=client -o yaml | kubectl apply -f -

# Create Vault CA secret
BAO_CLIENT_CA_BUNDLE="$PROTODIR/openbao/gen/crypto/openbao.ca"
kubectl create secret generic openbao-ca-secret \
        --from-file=ca.crt="$BAO_CLIENT_CA_BUNDLE" \
        --namespace=gatekeeper --dry-run=client -o yaml | kubectl apply -f -

HOST_IP=$(hostname -I | cut -f1 -d' ')
BAO_ADDR="https://$HOST_IP:8200"
BAO_CA_BUNDLE_B64=$(base64 -w0 < "$BAO_CLIENT_CA_BUNDLE")

# Deploy the gatekeeper-tls-issuer
kubectl apply -f- <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: gatekeeper-tls-issuer
  namespace: gatekeeper
spec:
  vault:
    path: nats_int/sign/gatekeeper-tls-issuer
    server: $BAO_ADDR
    caBundle: $BAO_CA_BUNDLE_B64
    auth:
      appRole:
        path: approle
        roleId: $ROLE_ID
        secretRef:
          name: gatekeeper-bao-approle
          key: secret-id
EOF

# Build the watcher microservice image.
/bin/bash $PROTODIR/scripts/buildGatekeeperImage.sh

# Generate the watcher pulsar client cert
kubectl -n gatekeeper apply -f $PROTODIR/kube-gatekeeper/gatekeeper-certificate.yaml

kubectl -n gatekeeper apply -f $PROTODIR/kube-gatekeeper/gatekeeper-bao-agent-configmap.yaml

kubectl -n gatekeeper apply -f $PROTODIR/kube-gatekeeper/gatekeeper-sa.yaml
kubectl -n gatekeeper apply -f $PROTODIR/kube-gatekeeper/gatekeeper-configmap.yaml
kubectl -n gatekeeper apply -f $PROTODIR/kube-gatekeeper/gatekeeper-role.yaml
kubectl -n gatekeeper apply -f $PROTODIR/kube-gatekeeper/gatekeeper-deployment.yaml
kubectl -n gatekeeper apply -f $PROTODIR/kube-gatekeeper/gatekeeper-service.yaml
