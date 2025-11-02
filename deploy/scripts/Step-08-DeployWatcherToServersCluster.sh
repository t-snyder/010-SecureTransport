#!/bin/bash
# Deploy Watcher for NATS JetStream with Simple mTLS Authorization
# Updated to match the simple mTLS approach from Step-06

# Switch to new terminal for servers cluster
minikube profile servers

PROTODIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy
SCHEMADIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/svc-core/src/main/resources/avro
CA_CERT_PATH="/openbao/userconfig/openbao-tls/openbao.ca"

# Deploy avro schemas for NATS watcher
kubectl create -n nats configmap avro-schemas --from-file=$SCHEMADIR/ --dry-run=client -o yaml | kubectl apply -f -

# Get Bao Agent Role ID (this can be considered public) and Secret ID which remains private
minikube profile bao

AGENT_ROLE_ID=$(kubectl exec -i -n openbao openbao-0 -- bao read -ca-cert=$CA_CERT_PATH -field=role_id auth/approle/role/watcher/role-id | tr -d '\r\n')
if [ -z "$AGENT_ROLE_ID" ]; then
    echo "Failed to retrieve ROLE_ID"
    exit 1
fi

AGENT_SECRET_ID=$(kubectl exec -i -n openbao openbao-0 -- bao write -ca-cert=$CA_CERT_PATH -field=secret_id -f auth/approle/role/watcher/secret-id | tr -d '\r\n')
if [ -z "$AGENT_SECRET_ID" ]; then
    echo "Failed to retrieve SECRET_ID"
    exit 1
fi

echo "Role ID: $AGENT_ROLE_ID"
echo "Secret ID: $AGENT_SECRET_ID"

# Use the cleaned variables to get the token
BAO_TOKEN=$(kubectl exec -i -n openbao openbao-0 -- sh << EOF
vault write -field=token auth/approle/login \
    role_id="$AGENT_ROLE_ID" \
    secret_id="$AGENT_SECRET_ID"
EOF
)

# Switch minikube profile back to servers
minikube profile servers

# Create Kubernetes secrets
kubectl create secret generic watcher-bao-approle \
        --from-literal=role-id="$AGENT_ROLE_ID" \
        --from-literal=secret-id="$AGENT_SECRET_ID" \
        --namespace=nats --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic nats-ca-secret \
        --from-file=ca.crt="$PROTODIR/openbao/gen/crypto/nats_ca_bundle.pem" \
        --namespace=nats --dry-run=client -o yaml | kubectl apply -f -

# Create Bao CA secret
BAO_ADDR="https://$(hostname -I | awk '{print $1}'):8200"
BAO_CLIENT_CA_BUNDLE="$PROTODIR/openbao/gen/crypto/openbao.ca"

# Debug: Check if file exists
if [[ ! -f "${BAO_CLIENT_CA_BUNDLE}" ]]; then
    echo "ERROR: CA bundle file not found at ${BAO_CLIENT_CA_BUNDLE}"
    ls -la "$PROTODIR/openbao/gen/crypto/" || echo "Directory doesn't exist"
    exit 1
fi

# Encode and verify
BAO_CLIENT_CA_B64="$(base64 -w0 < "${BAO_CLIENT_CA_BUNDLE}")"
echo "✓ CA bundle encoded successfully (${#BAO_CLIENT_CA_B64} characters)"

kubectl create secret generic openbao-ca-secret \
        --from-file=ca.crt="$BAO_CLIENT_CA_BUNDLE" \
        --namespace=nats --dry-run=client -o yaml | kubectl apply -f -

# Deploy the watcher-tls-issuer
kubectl apply -f- <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: watcher-tls-issuer
  namespace: nats
spec:
  vault:
    path: nats_int/sign/watcher-tls-issuer
    server: $BAO_ADDR
    caBundle: ${BAO_CLIENT_CA_B64}
    auth:
      appRole:
        path: approle
        roleId: $AGENT_ROLE_ID
        secretRef:
          name: watcher-bao-approle
          key: secret-id
EOF

# Build the watcher microservice image.
/bin/bash $PROTODIR/scripts/buildWatcherImage.sh


# Generate the watcher pulsar client cert
kubectl -n nats apply -f $PROTODIR/kube-watcher/watcher-certificate.yaml

kubectl -n nats apply -f $PROTODIR/kube-watcher/nats-bao-agent-configmap.yaml
kubectl -n nats apply -f $PROTODIR/kube-watcher/watcher-bao-agent-configmap.yaml

kubectl -n nats apply -f $PROTODIR/kube-watcher/watcher-sa.yaml
kubectl -n nats apply -f $PROTODIR/kube-watcher/watcher-configmap.yaml
kubectl -n nats apply -f $PROTODIR/kube-watcher/watcher-rbac.yaml
kubectl -n nats apply -f $PROTODIR/kube-watcher/watcher.yaml
kubectl -n nats apply -f $PROTODIR/kube-watcher/watcher-service.yaml

echo "=========================================="
echo "Watcher service deployed successfully!"
echo "=========================================="
