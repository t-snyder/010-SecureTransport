#!/bin/bash
# Step 09 - Deploy AuthController Service

set -euo pipefail

#-----------------------------
# Configurable Paths / Inputs
#-----------------------------
PROTODIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy
SCHEMADIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/svc-core/src/main/resources/avro
CA_CERT="/openbao/userconfig/openbao-tls/openbao.ca"

# Standardized NATS CA secret name expected by NatsTLSClient
NATS_CA_SECRET_NAME="nats-ca-secret"

AUTH_NAMESPACE="auth"
OPENBAO_NAMESPACE="openbao"

echo "[INFO] Using namespace: ${AUTH_NAMESPACE}"
echo "[INFO] NATS CA Secret Name: ${NATS_CA_SECRET_NAME}"

#-----------------------------
# Namespace
#-----------------------------
minikube profile services
kubectl create namespace "${AUTH_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

#-----------------------------
# Avro Schemas ConfigMap
#-----------------------------
echo "[INFO] Creating avro-schemas ConfigMap"
kubectl create -n "${AUTH_NAMESPACE}" configmap avro-schemas \
  --from-file="${SCHEMADIR}/" \
  --dry-run=client -o yaml | kubectl apply -f -

#========================================
# OpenBao (Vault) Setup for AuthController
#========================================
minikube profile bao

echo "[INFO] Creating authcontroller-tls-issuer role in OpenBao"
kubectl exec -n "${OPENBAO_NAMESPACE}" openbao-0 -i -- bao write -ca-cert="${CA_CERT}" nats_int/roles/authcontroller-tls-issuer \
  allowed_domains=authcontroller \
  allow_subdomains=true \
  allow_bare_domains=true \
  allow_any_name=true \
  max_ttl=12h \
  key_type=rsa \
  key_bits=4096

echo "[INFO] Creating authcontroller-tls-issuer policy"
kubectl exec -n "${OPENBAO_NAMESPACE}" openbao-0 -i -- bao policy write -ca-cert="${CA_CERT}" authcontroller-tls-issuer - <<EOF
path "nats_int/*"                                 { capabilities = ["read", "list"] }
path "nats_int/roles/authcontroller-tls-issuer"   { capabilities = ["read", "list", "create", "update"] }
path "nats_int/sign/authcontroller-tls-issuer"    { capabilities = ["create", "update"] }
path "nats_int/issue/authcontroller-tls-issuer"   { capabilities = ["create"] }
EOF

echo "[INFO] Creating authcontroller-policy"
kubectl exec -n "${OPENBAO_NAMESPACE}" openbao-0 -i -- bao policy write -ca-cert="${CA_CERT}" authcontroller-policy - <<EOF
path "secret/data/authcontroller/*" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# AppRole secret-id rotation
path "auth/approle/role/authcontroller/secret-id" {
  capabilities = ["update", "create"]
}

# PKI CA chain access
path "nats_int/ca_chain" {
  capabilities = ["read"]
}

# ServiceBundle read for authcontroller
path "secret/data/service-bundles/authcontroller/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/service-bundles/authcontroller/*" {
  capabilities = ["read", "list"]
}

# CaBundle read for NATS
path "secret/data/ca-bundles/NATS/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/ca-bundles/NATS/*" {
  capabilities = ["read", "list"]
}

# Allow reading metadata service bundles (for verification keys)
path "secret/data/service-bundles/metadata/*" {
  capabilities = ["read", "list"]
}
EOF

echo "[INFO] Creating AppRole: authcontroller"
kubectl exec -n "${OPENBAO_NAMESPACE}" openbao-0 -i -- bao write -ca-cert="${CA_CERT}" auth/approle/role/authcontroller \
    token_policies="authcontroller-policy,authcontroller-tls-issuer,signing-keys-read,authcontroller-signing-keys-write" \
    token_ttl=1d \
    token_max_ttl=1d \
    bind_secret_id=true \
    secret_id_ttl=12h \
    secret_id_num_uses=0

ROLE_ID=$(kubectl exec -i -n "${OPENBAO_NAMESPACE}" openbao-0 -- bao read -ca-cert="${CA_CERT}" -field=role_id auth/approle/role/authcontroller/role-id | tr -d '\r\n')
if [ -z "${ROLE_ID}" ]; then
    echo "[ERROR] Failed to retrieve ROLE_ID"; exit 1
fi

SECRET_ID=$(kubectl exec -i -n "${OPENBAO_NAMESPACE}" openbao-0 -- bao write -ca-cert="${CA_CERT}" -field=secret_id -f auth/approle/role/authcontroller/secret-id | tr -d '\r\n')
if [ -z "${SECRET_ID}" ]; then
    echo "[ERROR] Failed to retrieve SECRET_ID"; exit 1
fi

echo "[INFO] Retrieved ROLE_ID: ${ROLE_ID}"
echo "[INFO] Retrieved SECRET_ID: (hidden)"

#-----------------------------
# Switch back to services profile
#-----------------------------
minikube profile services

#-----------------------------
# Create AppRole Secret
#-----------------------------
echo "[INFO] Creating/Updating authcontroller-bao-approle secret"
kubectl create secret generic authcontroller-bao-approle \
  --from-literal=role-id="${ROLE_ID}" \
  --from-literal=secret-id="${SECRET_ID}" \
  -n "${AUTH_NAMESPACE}" \
  --dry-run=client -o yaml | kubectl apply -f -

#-----------------------------
# NATS CA Secret (standardized)
#-----------------------------
echo "[INFO] Creating/Updating ${NATS_CA_SECRET_NAME} (contains nats_ca.crt)"
kubectl create secret generic "${NATS_CA_SECRET_NAME}" \
  --from-file=ca.crt="${PROTODIR}/openbao/gen/crypto/nats_ca.crt" \
  -n "${AUTH_NAMESPACE}" \
  --dry-run=client -o yaml | kubectl apply -f -

# OPTIONAL: wait until API returns it (usually immediate)
# for i in {1..10}; do
#   if kubectl get secret "${NATS_CA_SECRET_NAME}" -n "${AUTH_NAMESPACE}" >/dev/null 2>&1; then
#     echo "[INFO] Verified ${NATS_CA_SECRET_NAME} exists."
#     break
#   fi
#   echo "[INFO] Waiting for ${NATS_CA_SECRET_NAME} ..."; sleep 1
# done

#-----------------------------
# OpenBao CA Secret (for Vault Agent / issuer)
#-----------------------------
BAO_CLIENT_CA_BUNDLE="${PROTODIR}/openbao/gen/crypto/openbao.ca"
echo "[INFO] Creating/Updating openbao-ca-secret"
kubectl create secret generic openbao-ca-secret \
  --from-file=ca.crt="${BAO_CLIENT_CA_BUNDLE}" \
  -n "${AUTH_NAMESPACE}" \
  --dry-run=client -o yaml | kubectl apply -f -

#-----------------------------
# Issuer referencing OpenBao
#-----------------------------
HOST_IP=$(hostname -I | cut -f1 -d' ')
BAO_ADDR="https://${HOST_IP}:8200"
BAO_CA_BUNDLE_B64=$(base64 -w0 < "${BAO_CLIENT_CA_BUNDLE}")

echo "[INFO] Applying authcontroller-tls-issuer (cert-manager Issuer)"
kubectl apply -f- <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: authcontroller-tls-issuer
  namespace: ${AUTH_NAMESPACE}
spec:
  vault:
    path: nats_int/sign/authcontroller-tls-issuer
    server: ${BAO_ADDR}
    caBundle: ${BAO_CA_BUNDLE_B64}
    auth:
      appRole:
        path: approle
        roleId: ${ROLE_ID}
        secretRef:
          name: authcontroller-bao-approle
          key: secret-id
EOF

#-----------------------------
# Build & Apply Manifests
#-----------------------------
echo "[INFO] Building AuthController image"
/bin/bash "${PROTODIR}/scripts/buildAuthControllerImage.sh"

echo "[INFO] Applying Kubernetes manifests"
kubectl -n "${AUTH_NAMESPACE}" apply -f "${PROTODIR}/kube-auth/authController-certificate.yaml"
kubectl -n "${AUTH_NAMESPACE}" apply -f "${PROTODIR}/kube-auth/authController-bao-agent-configmap.yaml"
kubectl -n "${AUTH_NAMESPACE}" apply -f "${PROTODIR}/kube-auth/authController-configmap.yaml"
kubectl -n "${AUTH_NAMESPACE}" apply -f "${PROTODIR}/kube-auth/authController-service-rbac.yaml"
kubectl -n "${AUTH_NAMESPACE}" apply -f "${PROTODIR}/kube-auth/authController-deployment.yaml"

echo "[INFO] Deployment script completed successfully."
