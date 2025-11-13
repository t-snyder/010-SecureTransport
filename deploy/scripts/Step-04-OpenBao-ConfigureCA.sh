#!/bin/bash

# Always regenerate CA certificates and store in KV store for cross-cluster sync

set -e
set -o pipefail

PROTODIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy
NAMESPACE="openbao"
POD_NAME="openbao-0"
CA_CERT_PATH="/openbao/userconfig/openbao-tls/openbao.ca"

# Helper for running bao inside the pod
bao_in_pod() {
    kubectl exec -i -n "$NAMESPACE" "$POD_NAME" -- bao "$@"
}

# Robust helper to list issuer IDs from a PKI mount regardless of JSON shape
list_issuer_ids() {
  local mount="$1"
  # Returns zero or more issuer IDs, one per line
  bao_in_pod list -ca-cert="$CA_CERT_PATH" -format=json "$mount/issuers" 2>/dev/null \
  | jq -r '
      if type=="object" then
        ( if (has("data") and (.data|type=="object") and (.data|has("keys"))) then .data.keys
          elif has("keys") then .keys
          else [] end )[]
      elif type=="array" then .[]
      else empty end
    ' || true
}

# Copy a local file into the pod and kv put it from inside the pod
kv_put_file() {
  local secret_path="$1"     # e.g. secret/nats/ca-bundle
  local key="$2"             # e.g. ca-bundle.pem
  local local_path="$3"      # local host path
  if [ ! -f "$local_path" ]; then
    echo "ERROR: kv_put_file: local file not found: $local_path"
    return 1
  fi
  local pod_tmp="/tmp/$(basename "$local_path").$$"
  echo "  - Staging $(basename "$local_path") into pod at $pod_tmp"
  kubectl cp "$local_path" -n "$NAMESPACE" "$POD_NAME:$pod_tmp"
  echo "  - Writing $secret_path ($key) to KV"
  bao_in_pod kv put -ca-cert="$CA_CERT_PATH" "$secret_path" "$key=@$pod_tmp"
  # Cleanup staged file
  kubectl exec -n "$NAMESPACE" "$POD_NAME" -- rm -f "$pod_tmp" || true
}

echo "=========================================="
echo "Step 04: Configure OpenBao PKI Infrastructure"
echo "=========================================="

# --- 1. Enable PKI and KV-v2 Secrets Engines ---
echo "Enabling PKI and KV-v2 secrets engines..."
bao_in_pod secrets enable -path=pki          -ca-cert="$CA_CERT_PATH" pki   || echo "PKI already enabled"
bao_in_pod secrets enable -path=secret       -ca-cert="$CA_CERT_PATH" kv-v2 || echo "KV-v2 already enabled"

# --- 2. Policy setup ---
echo "Setting up admin policy..."
cat "${PROTODIR}/openbao/policy/adminPolicy.hcl" | bao_in_pod policy write -ca-cert="$CA_CERT_PATH" admin -

echo "Listing policies..."
bao_in_pod policy list -ca-cert="$CA_CERT_PATH"
bao_in_pod policy read -ca-cert="$CA_CERT_PATH" admin

echo "Creating admin token..."
ADMIN_TOKEN=$(bao_in_pod token create -ca-cert="$CA_CERT_PATH" -format=json -policy="admin" | jq -r ".auth.client_token")
echo "ADMIN_TOKEN=$ADMIN_TOKEN"

echo "Testing admin token capabilities..."
bao_in_pod token capabilities -ca-cert="$CA_CERT_PATH" "$ADMIN_TOKEN" sys/auth/approle

# OpenBao address for CRL/issuing URLs
OPENBAO_ADDR="https://localhost:8200"


# --- 3. Root PKI Setup at 'pki' - Always regenerate ---

echo "=========================================="
echo "Regenerating Root CA (always)"
echo "=========================================="

# Generate a new timestamped root issuer
NEW_ROOT_NAME="root-$(date -u +%Y%m%d%H%M%S)"
echo "Generating new root CA with issuer name: $NEW_ROOT_NAME"
mkdir -p "$PROTODIR/openbao/gen/crypto"

# Save root cert to stable filename (no date)
ROOT_PEM="$PROTODIR/openbao/gen/crypto/root_ca.crt"

bao_in_pod write -ca-cert="$CA_CERT_PATH" -field=certificate pki/root/generate/internal \
    common_name="Root CA" \
    key_type=rsa \
    key_bits=4096 \
    issuer_name="$NEW_ROOT_NAME" \
    ttl=87600h > "$ROOT_PEM"

echo "New Root CA certificate saved to $ROOT_PEM"

echo "Root CA certificate dates:"
openssl x509 -in "$ROOT_PEM" -noout -subject -issuer -dates

echo "Configuring PKI URLs..."
bao_in_pod write -ca-cert="$CA_CERT_PATH" pki/config/urls \
    issuing_certificates="$OPENBAO_ADDR/v1/pki/ca" \
    crl_distribution_points="$OPENBAO_ADDR/v1/pki/crl" \
    ocsp_servers="$OPENBAO_ADDR/v1/ocsp"

echo "Creating root PKI role for general server certificates..."
bao_in_pod write -ca-cert="$CA_CERT_PATH" pki/roles/2025-servers \
    allow_any_name=true \
    allow_subdomains=true \
    key_type=rsa \
    key_bits=4096 \
    max_ttl="87600h"

# Set default issuer to the new root
echo "Setting default issuer for pki..."
ROOT_ISSUER_ID=""
for id in $(list_issuer_ids pki); do
  DATA=$(bao_in_pod read -ca-cert="$CA_CERT_PATH" -format=json pki/issuer/$id || true)
  [ -z "$DATA" ] && continue
  NAME=$(echo "$DATA" | jq -r '.data.issuer_name // .data.common_name // ""')
  if [[ "$NAME" == "$NEW_ROOT_NAME" ]]; then
    ROOT_ISSUER_ID="$id"
    break
  fi
done

if [ -n "$ROOT_ISSUER_ID" ]; then
  bao_in_pod write -ca-cert="$CA_CERT_PATH" pki/config/issuers default="$ROOT_ISSUER_ID"
  echo "Set default issuer for pki to: $ROOT_ISSUER_ID"
else
  echo "Warning: Could not find the new root issuer ID"
fi

################################################################################
# Nats Intermediate PKI Setup at 'nats_int' - Always regenerate
################################################################################
echo "=========================================="
echo "Regenerating Nats Intermediate CA (always)"
echo "=========================================="

echo "Ensuring nats_int mount exists..."
bao_in_pod secrets enable -ca-cert="$CA_CERT_PATH" -path=nats_int pki || echo "nats_int already enabled"
bao_in_pod secrets tune   -ca-cert="$CA_CERT_PATH" -max-lease-ttl=72h nats_int

echo "Generating new Nats intermediate CSR..."
mkdir -p "$PROTODIR/openbao/gen/csr" "$PROTODIR/openbao/gen/crypto"
bao_in_pod write -ca-cert="$CA_CERT_PATH" -format=json nats_int/intermediate/generate/internal \
    common_name="Nats Intermediate Authority" \
    key_type=rsa \
    key_bits=4096 \
    | jq -r '.data.csr' > "$PROTODIR/openbao/gen/csr/nats_intermediate.csr"

echo "Signing Nats intermediate CA with root..."
bao_in_pod write -ca-cert="$CA_CERT_PATH" -format=json pki/root/sign-intermediate \
    csr=- \
    format=pem_bundle \
    ttl="18h" \
    < "$PROTODIR/openbao/gen/csr/nats_intermediate.csr" \
    | jq -r '.data.certificate' > "$PROTODIR/openbao/gen/crypto/nats_ca.crt"

echo "Setting signed certificate for Nats intermediate CA..."
bao_in_pod write -ca-cert="$CA_CERT_PATH" nats_int/intermediate/set-signed certificate=- <<<"$(cat "$PROTODIR/openbao/gen/crypto/nats_ca.crt")"

echo "Finding and setting Nats intermediate issuer ID as default..."
NATS_ISSUER_ID=""
for id in $(list_issuer_ids nats_int); do
  ISSUER_DATA=$(bao_in_pod read -ca-cert="$CA_CERT_PATH" -format=json nats_int/issuer/$id || true)
  [ -z "$ISSUER_DATA" ] && continue
  ISSUER_NAME=$(echo "$ISSUER_DATA" | jq -r '.data.issuer_name // .data.common_name // ""')
  if [[ "$ISSUER_NAME" == *"Nats Intermediate Authority"* ]]; then
    echo "Nats Intermediate issuer ID is: $id"
    NATS_ISSUER_ID=$id
    break
  fi
done

if [ -n "$NATS_ISSUER_ID" ]; then
    echo "Setting default issuer for nats_int..."
    bao_in_pod write -ca-cert="$CA_CERT_PATH" nats_int/config/issuers default="$NATS_ISSUER_ID"
else
    echo "Warning: Could not determine NATS_ISSUER_ID for nats_int."
fi

echo "Configuring Nats PKI URLs..."
bao_in_pod write -ca-cert="$CA_CERT_PATH" nats_int/config/urls \
    issuing_certificates="$OPENBAO_ADDR/v1/nats_int/ca" \
    crl_distribution_points="$OPENBAO_ADDR/v1/nats_int/crl"

################################################################################
# Create CA Bundle Secrets for Kubernetes
################################################################################
echo "=========================================="
echo "Creating CA bundle secrets for Kubernetes"
echo "=========================================="

# Create Nats CA bundle (prefer assembling from local intermediate + root)
BUNDLE_PATH="$PROTODIR/openbao/gen/crypto/nats_ca_bundle.pem"
echo "Creating Nats CA bundle at $BUNDLE_PATH ..."
rm -f "$BUNDLE_PATH"
touch "$BUNDLE_PATH"

assemble_from_local=false
if [ -f "$PROTODIR/openbao/gen/crypto/nats_ca.crt" ] && [ -f "$ROOT_PEM" ]; then
  assemble_from_local=true
  cat "$PROTODIR/openbao/gen/crypto/nats_ca.crt" "$ROOT_PEM" > "$BUNDLE_PATH"
  echo "  Assembled bundle from local intermediate + root"
fi

# Validate bundle; if not valid, try to fetch from OpenBao and assemble
CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$BUNDLE_PATH" || echo "0")
if [ "$CERT_COUNT" -lt 2 ]; then
  echo "  Local assembly insufficient (found $CERT_COUNT certs). Trying to fetch CA chain from OpenBao..."
  # Try to get array of chain elements and print each element as PEM
  if bao_in_pod read -ca-cert="$CA_CERT_PATH" -format=json nats_int/cert/ca 2>/dev/null \
     | jq -r '
        if (.data.ca_chain // empty) != null then
          (.data.ca_chain[] | select(.!=null))
        elif (.data.certificate // empty) != null then
          .data.certificate
        else empty end
      ' > "$BUNDLE_PATH".tmp; then
    # If we only got the intermediate, append root
    CHAIN_CERTS=$(grep -c "BEGIN CERTIFICATE" "$BUNDLE_PATH".tmp || echo "0")
    if [ "$CHAIN_CERTS" -lt 2 ] && [ -f "$ROOT_PEM" ]; then
      cat "$BUNDLE_PATH".tmp "$ROOT_PEM" > "$BUNDLE_PATH"
    else
      mv "$BUNDLE_PATH".tmp "$BUNDLE_PATH"
    fi
    rm -f "$BUNDLE_PATH".tmp || true
    echo "  Fetched CA chain from OpenBao and assembled bundle"
  else
    echo "  Warning: failed to fetch from OpenBao. Keeping local assembly."
  fi
fi

# Final validation: require at least 2 certs
CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$BUNDLE_PATH" || echo "0")
BUNDLE_SIZE=$(wc -c < "$BUNDLE_PATH" || echo "0")
echo "  Nats CA bundle contains $CERT_COUNT certificate(s), size: $BUNDLE_SIZE bytes"

if [ "$CERT_COUNT" -lt 2 ] || [ "$BUNDLE_SIZE" -lt 100 ]; then
  echo "ERROR: Nats CA bundle is invalid. Aborting to avoid pushing bad data to KV."
  exit 1
fi

# Create/update the Nats CA bundle secret in the openbao namespace
kubectl create secret generic nats-ca-bundle \
  --from-file=ca-bundle.pem="$BUNDLE_PATH" \
  -n openbao --dry-run=client -o yaml | kubectl apply -f -
echo "Created/updated Nats CA bundle secret in namespace 'openbao'"


################################################################################
# Verify Setup
################################################################################
echo "=========================================="
echo "Verifying PKI Setup"
echo "=========================================="

echo "Root CA certificate dates:"
if [ -f "$ROOT_PEM" ]; then
    openssl x509 -in "$ROOT_PEM" -noout -subject -issuer -dates
fi

echo "Nats Intermediate CA certificate dates:"
if [ -f "$PROTODIR/openbao/gen/crypto/nats_ca.crt" ]; then
    openssl x509 -in "$PROTODIR/openbao/gen/crypto/nats_ca.crt" -noout -subject -issuer -dates
fi

echo "Current issuer configs:"
echo "  pki:"
bao_in_pod read -ca-cert="$CA_CERT_PATH" pki/config/issuers || true
echo "  nats_int:"
bao_in_pod read -ca-cert="$CA_CERT_PATH" nats_int/config/issuers || true

# Verify CA bundle contents
echo "CA Bundle verification:"
if [ -f "$BUNDLE_PATH" ]; then
  CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$BUNDLE_PATH" || echo "0")
  BUNDLE_SIZE=$(wc -c < "$BUNDLE_PATH")
  echo "  Nats CA bundle contains $CERT_COUNT certificate(s), size: $BUNDLE_SIZE bytes"
fi

echo "=========================================="
echo "PKI Configuration Complete!"
echo "- All certificates regenerated with 72h TTL"
echo "=========================================="
