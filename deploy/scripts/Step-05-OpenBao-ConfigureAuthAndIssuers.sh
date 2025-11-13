#!/bin/bash

# OpenBao AppRole Authentication Setup Script

set -e

PROTODIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy
CA_CERT_PATH="/openbao/userconfig/openbao-tls/openbao.ca"

wait_for_openbao() {
    echo "Waiting for OpenBao to be ready..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        echo "Attempt $attempt of $max_attempts: Checking OpenBao status..."
        if kubectl exec -n openbao openbao-0 -- bao status -ca-cert=$CA_CERT_PATH > /dev/null 2>&1; then
            echo "OpenBao is ready!"
            return 0
        else
            echo "OpenBao not ready yet, waiting 10 seconds..."
            sleep 10
            ((attempt++))
        fi
    done
    echo "OpenBao did not become ready within the expected time"
    return 1
}

authenticate_with_retry() {
    local token=$1
    local max_attempts=5
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        echo "Authentication attempt $attempt of $max_attempts..."
        if kubectl exec -n openbao openbao-0 -- bao login -ca-cert=$CA_CERT_PATH $token > /dev/null 2>&1; then
            echo "Authentication successful!"
            return 0
        else
            echo "Authentication failed, retrying in 5 seconds..."
            sleep 5
            ((attempt++))
        fi
    done
    echo "Authentication failed after $max_attempts attempts"
    return 1
}

wait_for_openbao

ROOT_TOKEN=$(jq -r .root_token $PROTODIR/openbao/gen/crypto/cluster-keys.json)

echo "Logging in with ROOT token..."

if authenticate_with_retry $ROOT_TOKEN; then
    echo "ROOT token authentication successful"
else
    echo "Failed to authenticate with ROOT token"
    exit 1
fi

echo "Creating new ADMIN_TOKEN..."
kubectl exec -n openbao openbao-0 -- bao token create -ca-cert=$CA_CERT_PATH -format=json -policy="admin" > $PROTODIR/openbao/gen/crypto/admin_token.json

ADMIN_TOKEN=$(jq -r ".auth.client_token" $PROTODIR/openbao/gen/crypto/admin_token.json)
echo "Creating new ADMIN_TOKEN = $ADMIN_TOKEN"

echo "Re-authenticating with OpenBao using admin token..."
if authenticate_with_retry $ADMIN_TOKEN; then
    echo "ADMIN token authentication successful"
else
    echo "Failed to authenticate with ADMIN token"
    exit 1
fi

echo "Verifying authentication..."
kubectl exec -n openbao openbao-0 -- bao token lookup -ca-cert=$CA_CERT_PATH

echo "Enabling approle authentication..."
if kubectl exec -n openbao openbao-0 -- bao auth enable -ca-cert=$CA_CERT_PATH approle 2>/dev/null; then
    echo "AppRole auth method enabled successfully"
else
    echo "AppRole auth method already enabled"
fi

echo "Creating KV secrets engine path for signing keys if not exists..."
kubectl exec -n openbao openbao-0 -- bao secrets list -ca-cert=$CA_CERT_PATH | grep -q "secret/" || \
    kubectl exec -n openbao openbao-0 -- openbao secrets enable -ca-cert=$CA_CERT_PATH -path=secret kv-v2

echo "Creating policy for reading signing keys..."
kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert=$CA_CERT_PATH signing-keys-read - <<EOF
path "secret/data/signing-keys/*" {
  capabilities = ["read", "list"]
}
EOF

echo "Creating policy for writing signing keys..."
kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert=$CA_CERT_PATH nats-signing-keys-write - <<EOF
path "secret/data/signing-keys/nats/*" {
  capabilities = ["create", "update", "read", "delete", "list"]
}
EOF

kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert=$CA_CERT_PATH metadata-signing-keys-write - <<EOF
path "secret/data/signing-keys/metadata/*" {
  capabilities = ["create", "update", "read", "delete", "list"]
}
EOF

kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert=$CA_CERT_PATH watcher-signing-keys-write - <<EOF
path "secret/data/signing-keys/watcher/*" {
  capabilities = ["create", "update", "read", "delete", "list"]
}
EOF

###########################################################################################
echo "Creating nats-tls-issuer role..."
kubectl exec -n openbao openbao-0 -i -- bao write -ca-cert=$CA_CERT_PATH nats_int/roles/nats-tls-issuer \
  allowed_domains=nats \
  allow_subdomains=true \
  allow_bare_domains=true \
  allow_any_name=true \
  max_ttl=12h \
  key_type=rsa \
  key_bits=4096

echo "Creating bats-tls-issuer policy..."
kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert=$CA_CERT_PATH nats-tls-issuer - <<EOF
path "nats_int/*"                     { capabilities = ["read", "list"] }
path "nats_int/roles/nats-tls-issuer" { capabilities = ["read", "list", "create", "update"] }
path "nats_int/sign/nats-tls-issuer"  { capabilities = ["create", "update"] }
path "nats_int/issue/nats-tls-issuer" { capabilities = ["create"] }
EOF

kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert=$CA_CERT_PATH nats-ca-admin - <<EOF
path "nats_int/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "pki/root/sign-intermediate" {
  capabilities = ["create", "update"]
}
EOF

echo "Creating policy: nats-policy"
kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert=$CA_CERT_PATH nats-policy - <<EOF
path "secret/data/nats/*" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "auth/approle/role/nats/secret-id" {
  capabilities = ["update", "create"]
}
EOF

echo "Creating AppRole: nats"
kubectl exec -n openbao openbao-0 -i -- bao write -ca-cert=$CA_CERT_PATH auth/approle/role/nats \
    token_policies="nats-policy,nats-tls-issuer,signing-keys-read" \
    token_ttl=1d \
    token_max_ttl=1d \
    bind_secret_id=true \
    secret_id_ttl=12h \
    secret_id_num_uses=0

###########################################################################################
echo "Creating metadata-tls-issuer role..."
kubectl exec -n openbao openbao-0 -i -- bao write -ca-cert=$CA_CERT_PATH nats_int/roles/metadata-tls-issuer \
  allowed_domains=metadata.nats \
  allow_subdomains=true \
  allow_bare_domains=true \
  allow_any_name=true \
  max_ttl=12h \
  key_type=rsa \
  key_bits=4096

echo "Creating metadata-tls-issuer policy..."
kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert=$CA_CERT_PATH metadata-tls-issuer - <<EOF
path "nats_int/roles/metadata-tls-issuer"   { capabilities = ["read", "list", "create", "update"] }
path "nats_int/sign/metadata-tls-issuer"    { capabilities = ["create", "update"] }
path "nats_int/issue/metadata-tls-issuer"   { capabilities = ["create"] }
path "nats_int/cert/ca"                     { capabilities = ["read"] }
path "nats_int/ca_chain"                    { capabilities = ["read"] }
path "nats_int/crl"                         { capabilities = ["read"] }
EOF

echo "Creating policy: metadata-policy"
echo "Creating policy: metadata-policy"
kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert=$CA_CERT_PATH metadata-policy - <<EOF
# Basic metadata secrets access
path "secret/data/metadata/*" {
  capabilities = ["read"]
}

# Token management
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# AppRole secret-id rotation
path "auth/approle/role/metadata/secret-id" {
  capabilities = ["update", "create"]
}

# Legacy metadata PKI (if still used)
path "metadata_pki/issue/service-role" {
  capabilities = ["create", "update"]
}

path "metadata_pki/ca" {
  capabilities = ["read"]
}

path "metadata_pki/ca_chain" {
  capabilities = ["read"]
}

path "metadata_pki/crl" {
  capabilities = ["read"]
}

path "metadata_pki/revoke" {
  capabilities = ["create", "update"]
}

# NATS CA chain read access
path "nats_int/ca_chain" {
  capabilities = ["read"]
}

# === NEW: CA ROTATION PERMISSIONS ===

# PKI Issuer Management (for CA rotation)
path "nats_int/issuer/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "nats_int/issuers" {
  capabilities = ["list", "read"]
}

# PKI Key Management (for CA rotation with new keys)
path "nats_int/key/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "nats_int/keys" {
  capabilities = ["list", "read"]
}

# Generate new keys
path "nats_int/keys/generate/internal" {
  capabilities = ["create", "update"]
}

# Intermediate CA generation
path "nats_int/intermediate/generate/internal" {
  capabilities = ["create", "update"]
}

# Import signed certificates
path "nats_int/intermediate/set-signed" {
  capabilities = ["create", "update"]
}

# Import certificate bundles
path "nats_int/issuers/import/cert" {
  capabilities = ["create", "update"]
}

# Root CA signing (for intermediate certs)
path "pki/root/sign-intermediate" {
  capabilities = ["create", "update"]
}

# PKI configuration
path "nats_int/config/issuers" {
  capabilities = ["read", "update"]
}

path "nats_int/config/keys" {
  capabilities = ["read", "update"]
}

# Read root CA for signing
path "pki/cert/ca" {
  capabilities = ["read"]
}

path "pki/ca_chain" {
  capabilities = ["read"]
}

# === END CA ROTATION PERMISSIONS ===

# Service bundles storage
path "secret/data/service-bundles/*" {
  capabilities = ["create", "update", "read", "list"]
}

path "secret/metadata/service-bundles/*" {
  capabilities = ["read", "list", "delete"]
}

# CA bundles storage
path "secret/data/ca-bundles/*" {
  capabilities = ["create", "update", "read", "list"]
}

path "secret/metadata/ca-bundles/*" {
  capabilities = ["read", "list", "delete"]
}
EOF

echo "Creating AppRole: metadata"
kubectl exec -n openbao openbao-0 -i -- bao write -ca-cert=$CA_CERT_PATH auth/approle/role/metadata \
    token_policies="metadata-policy,metadata-tls-issuer,signing-keys-read,metadata-signing-keys-write,metadata-pki-admin,nats-ca-admin" \
    token_ttl=1d \
    token_max_ttl=1d \
    bind_secret_id=true \
    secret_id_ttl=12h \
    secret_id_num_uses=0

###########################################################################################
echo "Creating watcher-tls-issuer role..."
kubectl exec -n openbao openbao-0 -i -- bao write -ca-cert=$CA_CERT_PATH nats_int/roles/watcher-tls-issuer \
  allowed_domains=watcher \
  allow_subdomains=true \
  allow_bare_domains=true \
  allow_any_name=true \
  max_ttl=12h \
  key_type=rsa \
  key_bits=4096

echo "Creating watcher-tls-issuer policy..."
kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert=$CA_CERT_PATH watcher-tls-issuer - <<EOF
path "nats_int/*"                          { capabilities = ["read", "list"] }
path "nats_int/roles/watcher-tls-issuer"   { capabilities = ["read", "list", "create", "update"] }
path "nats_int/sign/watcher-tls-issuer"    { capabilities = ["create", "update"] }
path "nats_int/issue/watcher-tls-issuer"   { capabilities = ["create"] }
EOF

echo "Creating policy: watcher-policy"
kubectl exec -n openbao openbao-0 -i -- bao policy write -ca-cert=$CA_CERT_PATH watcher-policy - <<EOF
path "secret/data/watcher/*" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# AppRole secret-id rotation
path "auth/approle/role/watcher/secret-id" {
  capabilities = ["update", "create"]
}

# PKI CA chain access
path "nats_int/ca_chain" {
  capabilities = ["read"]
}

# ServiceBundle read for watcher
path "secret/data/service-bundles/watcher/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/service-bundles/watcher/*" {
  capabilities = ["read", "list"]
}

# CaBundle read for NATS
path "secret/data/ca-bundles/NATS/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/ca-bundles/NATS/*" {
  capabilities = ["read", "list"]
}

# Alow reading metadata service bundles
path "secret/data/service-bundles/metadata/*" {
  capabilities = ["read", "list"]
}
EOF

echo "Creating AppRole: watcher"
kubectl exec -n openbao openbao-0 -i -- bao write -ca-cert=$CA_CERT_PATH auth/approle/role/watcher \
    token_policies="watcher-policy,watcher-tls-issuer,signing-keys-read,watcher-signing-keys-write" \
    token_ttl=1d \
    token_max_ttl=1d \
    bind_secret_id=true \
    secret_id_ttl=12h \
    secret_id_num_uses=0

echo "OpenBao is set up for CA cert signing, AppRole authentication, and secrets"
