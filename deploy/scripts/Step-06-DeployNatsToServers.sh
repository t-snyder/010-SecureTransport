#!/bin/bash
# Deploy NATS JetStream with mTLS using manifests (no Helm, no Operator).
# Refactored to render per-pod nats.conf at startup (probe TLS/TCP on 6222)
# and use OrderedReady StatefulSet to avoid route churn.
set -euo pipefail

# ---------- Config (override via env) ----------
PROTODIR="${PROTODIR:-/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy}"
CLUSTER="${CLUSTER:-servers}"
BAO_PROFILE="${BAO_PROFILE:-bao}"
SERVERS_PROFILE="${SERVERS_PROFILE:-servers}"
NATS_NAMESPACE="${NATS_NAMESPACE:-nats}"
NATS_CLUSTER_NAME="${NATS_CLUSTER_NAME:-nats-cluster}"
NATS_REPLICAS="${NATS_REPLICAS:-3}"
NATS_JS_MEM="${NATS_JS_MEM:-1GB}"
NATS_JS_FILE="${NATS_JS_FILE:-10Gi}"
CA_CERT_PATH="${CA_CERT_PATH:-/openbao/userconfig/openbao-tls/openbao.ca}"
BAO_CLIENT_CA_BUNDLE="${BAO_CLIENT_CA_BUNDLE:-${PROTODIR}/openbao/gen/crypto/openbao.ca}"
NATS_VERSION="${NATS_VERSION:-2.10.22}"
NATS_IMAGE="${NATS_IMAGE:-nats:${NATS_VERSION}-alpine}"
NATS_CLIENT_IMAGE="${NATS_CLIENT_IMAGE:-natsio/nats-box:0.18.1}"
ACCESS_IP="${ACCESS_IP:-10.1.1.12}"
# ------------------------------------------------

command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found in PATH"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not found in PATH"; exit 1; }
command -v nc >/dev/null 2>&1 || echo "Warning: nc not found, connection wait may fail"

function minikube_profile() {
  if command -v minikube >/dev/null 2>&1; then
    minikube profile "$1"
  fi
}

echo "Switch to OpenBao profile to fetch CA/approle..."
minikube_profile "${BAO_PROFILE}"

# --------------------------
# Retrieve OpenBao AppRole (existing approach)
# --------------------------
ROLE_ID=$(kubectl exec -i -n openbao openbao-0 -- bao read -ca-cert="${CA_CERT_PATH}" -field=role_id auth/approle/role/nats/role-id 2>/dev/null | tr -d '\r\n' || true)
if [[ -z "${ROLE_ID}" ]]; then
  echo "Failed to retrieve ROLE_ID from OpenBao"
  exit 1
fi
SECRET_ID=$(kubectl exec -i -n openbao openbao-0 -- bao write -ca-cert="${CA_CERT_PATH}" -field=secret_id -f auth/approle/role/nats/secret-id 2>/dev/null | tr -d '\r\n' || true)
if [[ -z "${SECRET_ID}" ]]; then
  echo "Failed to retrieve SECRET_ID from OpenBao"
  exit 1
fi

echo "ROLE_ID and SECRET_ID obtained."

# --------------------------
# Build CA bundle from OpenBao
# --------------------------
TMP_CA_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_CA_DIR"' EXIT

echo "Fetching CA certs from OpenBao..."
kubectl exec -n openbao openbao-0 -- bao read -ca-cert="${CA_CERT_PATH}" -format=json nats_int/cert/ca | jq -r '.data.certificate' > "${TMP_CA_DIR}/nats_ca_raw.crt"
kubectl exec -n openbao openbao-0 -- bao read -ca-cert="${CA_CERT_PATH}" -format=json pki/cert/ca | jq -r '.data.certificate' > "${TMP_CA_DIR}/root_ca_raw.crt"

# sanitize and assemble
tr -d '\r' < "${TMP_CA_DIR}/nats_ca_raw.crt" | sed '/^$/d' > "${TMP_CA_DIR}/nats_ca.crt"
tr -d '\r' < "${TMP_CA_DIR}/root_ca_raw.crt" | sed '/^$/d' > "${TMP_CA_DIR}/root_ca.crt"
echo "" >> "${TMP_CA_DIR}/nats_ca.crt"
echo "" >> "${TMP_CA_DIR}/root_ca.crt"
cat "${TMP_CA_DIR}/nats_ca.crt" "${TMP_CA_DIR}/root_ca.crt" > "${TMP_CA_DIR}/fresh_ca_bundle.pem"

CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "${TMP_CA_DIR}/fresh_ca_bundle.pem" || true)
if [[ "${CERT_COUNT}" -lt 1 ]]; then
  echo "ERROR: CA bundle creation failed"
  exit 1
fi
echo "Created CA bundle with ${CERT_COUNT} certificate(s)."

cp "${TMP_CA_DIR}/fresh_ca_bundle.pem" "${PROTODIR}/openbao/gen/crypto/nats_ca_bundle.pem"
echo "CA bundle saved to ${PROTODIR}/openbao/gen/crypto/nats_ca_bundle.pem"

# --------------------------
# Switch back to servers context and create namespace + secrets
# --------------------------
minikube_profile "${SERVERS_PROFILE}"

kubectl --context="${CLUSTER}" create namespace "${NATS_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

kubectl --context="${CLUSTER}" create secret generic nats-bao-approle \
  --from-literal=role-id="${ROLE_ID}" \
  --from-literal=secret-id="${SECRET_ID}" \
  --namespace="${NATS_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# create CA secret (stringData for readability)
CA_PEM="$(sed 's/^/    /' "${TMP_CA_DIR}/fresh_ca_bundle.pem" | sed -e '1,$p' -n)"
kubectl --context="${CLUSTER}" apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: nats-ca-tls
  namespace: ${NATS_NAMESPACE}
type: Opaque
stringData:
  ca.crt: |
${CA_PEM}
EOF

if [[ -f "${BAO_CLIENT_CA_BUNDLE}" ]]; then
  BAO_CLIENT_CA="$(sed 's/^/    /' "${BAO_CLIENT_CA_BUNDLE}" | sed -e '1,$p' -n)"
  kubectl --context="${CLUSTER}" apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: openbao-ca-secret
  namespace: ${NATS_NAMESPACE}
type: Opaque
stringData:
  ca.crt: |
${BAO_CLIENT_CA}
EOF
else
  echo "Warning: BAO client CA bundle not found at ${BAO_CLIENT_CA_BUNDLE}; continue if not required"
fi

# --------------------------
# Create cert-manager Issuer and Certificates
# --------------------------
BAO_ADDR="https://$(hostname -I | awk '{print $1}'):8200"
BAO_CLIENT_CA_B64="$(base64 -w0 < "${BAO_CLIENT_CA_BUNDLE}" 2>/dev/null || true)"

kubectl --context="${CLUSTER}" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: nats-tls-issuer
  namespace: ${NATS_NAMESPACE}
spec:
  vault:
    path: nats_int/sign/nats-tls-issuer
    server: ${BAO_ADDR}
    caBundle: ${BAO_CLIENT_CA_B64}
    auth:
      appRole:
        path: approle
        roleId: ${ROLE_ID}
        secretRef:
          name: nats-bao-approle
          key: secret-id
EOF

echo "Deploying certificate nats-server-tls"
kubectl --context="${CLUSTER}" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: nats-server-tls
  namespace: nats
spec:
  secretName: nats-server-tls
  issuerRef:
    name: nats-tls-issuer
    kind: Issuer
  commonName: nats-server
  dnsNames:
  - nats.nats.svc.cluster.local
  - nats-headless.nats.svc.cluster.local
  - nats-0.nats-headless.nats.svc.cluster.local
  - nats-1.nats-headless.nats.svc.cluster.local
  - nats-2.nats-headless.nats.svc.cluster.local
  - nats
  - localhost
  ipAddresses:
  - 127.0.0.1
  - ${ACCESS_IP}
  duration: 12h
  renewBefore: 2h
  privateKey:
    algorithm: RSA
    size: 4096
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF

echo "Waiting for certificates to be issued (nats-server-tls)..."
kubectl --context="${CLUSTER}" wait --for=condition=ready certificate/nats-server-tls -n nats --timeout=300s || echo "Certificate not ready yet, continue and verify later"

# --------------------------
# Create ConfigMap template with render script (nats.conf.tpl + render-config-tcp.sh)
# The initContainer will render a per-pod nats.conf into /etc/nats-config
# --------------------------
kubectl --context="${CLUSTER}" apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: nats-config
  namespace: nats
data:
  nats.conf: |
    port: 4222
    server_name: \$POD_NAME

    jetstream {
      store_dir: /data
      max_file_store: 10Gi
    }
    
    cluster {
      name: nats
      port: 6222
      routes: [
        nats://nats-0.nats-headless.nats.svc.cluster.local:6222
        nats://nats-1.nats-headless.nats.svc.cluster.local:6222
        nats://nats-2.nats-headless.nats.svc.cluster.local:6222
      ]
      
      tls {
        cert_file: /etc/nats-server-tls-certs/tls.crt
        key_file: /etc/nats-server-tls-certs/tls.key
        ca_file: /etc/nats-ca-certs/ca.crt
        verify: false
        timeout: 5
      }
    }
    
    tls {
      cert_file: /etc/nats-server-tls-certs/tls.crt
      key_file: /etc/nats-server-tls-certs/tls.key
      ca_file: /etc/nats-ca-certs/ca.crt
      verify: true
      timeout: 5
    }
EOF

# --------------------------
# Deploy NATS StatefulSet (initContainer renders per-pod config)
# --------------------------
echo "Deploying NATS StatefulSet (version ${NATS_VERSION}) with dynamic per-pod rendering"

kubectl --context="${CLUSTER}" apply -f - <<EOF
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: nats
  namespace: nats
spec:
  serviceName: nats-headless
  replicas: 3
  podManagementPolicy: OrderedReady
  selector:
    matchLabels:
      app: nats
  template:
    metadata:
      labels:
        app: nats
    spec:
      containers:
      - name: nats
        image: nats:2.11.9-alpine
        command:
        - nats-server
        - --config
        - /etc/nats-config/nats.conf
        ports:
        - containerPort: 4222
          name: client
        - containerPort: 8222
          name: monitor
        - containerPort: 6222
          name: cluster

        volumeMounts:
        - name: nats-config
          mountPath: /etc/nats-config
        - name: server-tls-certs
          mountPath: /etc/nats-server-tls-certs
        - name: ca-certs
          mountPath: /etc/nats-ca-certs
        - name: data
          mountPath: /data
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name

      volumes:
      - name: nats-config
        configMap:
          name: nats-config
      - name: ca-certs
        secret:
          secretName: nats-ca-tls
      - name: server-tls-certs
        secret:
          secretName: nats-server-tls

  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
EOF

# Services (headless + cluster service)
kubectl --context="${CLUSTER}" apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: nats-headless
  namespace: nats
spec:
  clusterIP: None
  selector:
    app: nats
  ports:
  - name: client
    port: 4222
  - name: cluster
    port: 6222
  - name: monitor
    port: 8222
---
apiVersion: v1
kind: Service
metadata:
  name: nats
  namespace: ${NATS_NAMESPACE}
spec:
  selector:
    app: nats
  ports:
  - name: client
    port: 4222
    targetPort: 4222
  - name: monitor
    port: 8222
    targetPort: 8222
  type: LoadBalancer
EOF

echo "Waiting for NATS pods (statefulset) to be ready..."
kubectl --context="${CLUSTER}" -n "${NATS_NAMESPACE}" rollout status statefulset/nats --timeout=600s || echo "NATS rollout did not finish in time; inspect pods"

# Verify a pod's config exists
kubectl --context="${CLUSTER}" -n "${NATS_NAMESPACE}" exec nats-0 -- cat /etc/nats-config/nats.conf || echo "nats.conf not present yet on nats-0"

# --------------------------
# Setup JetStream streams - create client cert + transient pod
# --------------------------
kubectl --context="${CLUSTER}" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: nats-client-tls
  namespace: ${NATS_NAMESPACE}
spec:
  secretName: nats-client-tls
  issuerRef:
    name: nats-tls-issuer
    kind: Issuer
  commonName: nats-client
  duration: 12h
  renewBefore: 2h
  privateKey:
    algorithm: RSA
    size: 4096
  usages:
    - digital signature
    - key encipherment
    - client auth
EOF

kubectl --context="${CLUSTER}" wait --for=condition=ready certificate/nats-client-tls -n "${NATS_NAMESPACE}" --timeout=300s || echo "Client cert not ready yet"

kubectl --context="${CLUSTER}" apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nats-client
  namespace: nats
spec:
  restartPolicy: Never
  containers:
  - name: nats-client
    image: ${NATS_CLIENT_IMAGE}
    imagePullPolicy: Always
    command: ["sleep", "3600"]
    volumeMounts:
    - name: client-tls-certs
      mountPath: /etc/nats-client-tls-certs
    - name: ca-certs
      mountPath: /etc/nats-ca-certs
  volumes:
  - name: client-tls-certs
    secret:
      secretName: nats-client-tls
  - name: ca-certs
    secret:
      secretName: nats-ca-tls
EOF

kubectl --context="${CLUSTER}" wait --for=condition=ready pod/nats-client -n "${NATS_NAMESPACE}" --timeout=120s || echo "nats-client pod not ready yet; you may create streams manually"

echo "Creating JetStream streams (idempotent)..."
# Use the headless service for internal cluster access
NATS_SERVICE="nats.${NATS_NAMESPACE}.svc.cluster.local"

# Helper function to run nats commands
run_nats_cmd() {
  kubectl --context="${CLUSTER}" exec -n "${NATS_NAMESPACE}" nats-client -- /bin/sh -c "$1"
}

# Create streams one by one with proper error handling
echo "Creating stream KEY_EXCHANGE..."
run_nats_cmd "nats stream add KEY_EXCHANGE \
  --server=tls://${NATS_SERVICE}:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt \
  --subjects='metadata.key-exchange.>' \
  --storage=file \
  --retention=limits \
  --discard=old \
  --replicas=3 \
  --max-age=1h \
  --no-allow-rollup \
  --deny-delete \
  --deny-purge \
  --defaults" || echo 'Stream KEY_EXCHANGE may already exist'

echo "Creating stream METADATA_CLIENT..."
run_nats_cmd "nats stream add METADATA_CLIENT \
  --server=tls://${NATS_SERVICE}:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt \
  --subjects='metadata.client.>' \
  --storage=file \
  --retention=limits \
  --discard=old \
  --replicas=3 \
  --max-age=24h \
  --no-allow-rollup \
  --deny-delete \
  --deny-purge \
  --defaults" || echo 'Stream METADATA_CLIENT may already exist'

echo "Creating stream METADATA_BUNDLE_PULL..."
run_nats_cmd "nats stream add METADATA_BUNDLE_PULL \
  --server=tls://${NATS_SERVICE}:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt \
  --subjects='metadata.bundle-pull.>' \
  --storage=file \
  --retention=limits \
  --discard=old \
  --replicas=3 \
  --max-age=2h \
  --no-allow-rollup \
  --deny-delete \
  --deny-purge \
  --defaults" || echo 'Stream METADATA_BUNDLE_PULL may already exist'

echo "Creating stream METADATA_BUNDLE_PUSH..."
run_nats_cmd "nats stream add METADATA_BUNDLE_PUSH \
  --server=tls://${NATS_SERVICE}:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt \
  --subjects='metadata.bundle-push.>' \
  --storage=file \
  --retention=limits \
  --discard=old \
  --replicas=3 \
  --max-age=6h \
  --no-allow-rollup \
  --deny-delete \
  --deny-purge \
  --defaults" || echo 'Stream METADATA_BUNDLE_PUSH may already exist'

echo "Creating stream AUTH_STREAM..."
run_nats_cmd "nats stream add AUTH_STREAM \
  --server=tls://${NATS_SERVICE}:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt \
  --subjects='auth.>' \
  --storage=file \
  --retention=limits \
  --discard=old \
  --replicas=3 \
  --max-age=1h \
  --no-allow-rollup \
  --deny-delete \
  --deny-purge \
  --defaults" || echo 'Stream AUTH_STREAM may already exist'

echo "Creating stream GATEKEEPER_STREAM..."
run_nats_cmd "nats stream add GATEKEEPER_STREAM \
  --server=tls://${NATS_SERVICE}:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt \
  --subjects='gatekeeper.>' \
  --storage=file \
  --retention=limits \
  --discard=old \
  --replicas=3 \
  --max-age=1h \
  --no-allow-rollup \
  --deny-delete \
  --deny-purge \
  --defaults" || echo 'Stream GATEKEEPER_STREAM may already exist'

echo '=== Stream List ==='
run_nats_cmd "nats stream list \
  --server=tls://${NATS_SERVICE}:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt" || true

echo "=== Ensuring JetStream consumers (idempotent) ==="

# Helper function to add consumer with existence check
add_consumer() {
  local stream=$1
  local consumer=$2
  local subject=$3
  local group=$4
  
  echo "Push consumer ${consumer} on stream ${stream}..."
  run_nats_cmd "
    if nats consumer info ${stream} ${consumer} \
      --server=tls://${NATS_SERVICE}:4222 \
      --tlscert=/etc/nats-client-tls-certs/tls.crt \
      --tlskey=/etc/nats-client-tls-certs/tls.key \
      --tlsca=/etc/nats-ca-certs/ca.crt >/dev/null 2>&1; then
      echo 'already exists'
    else
      nats consumer add ${stream} ${consumer} \
        --server=tls://${NATS_SERVICE}:4222 \
        --tlscert=/etc/nats-client-tls-certs/tls.crt \
        --tlskey=/etc/nats-client-tls-certs/tls.key \
        --tlsca=/etc/nats-ca-certs/ca.crt \
        --deliver=last \
        --target='${subject}' \
        --deliver-group='${group}' \
        --ack=explicit \
        --flow-control \
        --heartbeat=2s \
        --max-pending=200 \
        --defaults && echo 'created' || echo 'create failed'
    fi
  "
}

# METADATA_BUNDLE_PUSH consumers
add_consumer "METADATA_BUNDLE_PUSH" "metadata-bundle-push-watcher" "deliver.metadata.bundle-push.svc-watcher" "metadata-bundle-push-watcher"
add_consumer "METADATA_BUNDLE_PUSH" "metadata-bundle-push-tester" "deliver.metadata.bundle-push.svc-tester" "metadata-bundle-push-tester"
add_consumer "METADATA_BUNDLE_PUSH" "metadata-bundle-push-authcontroller" "deliver.metadata.bundle-push.svc-authcontroller" "metadata-bundle-push-authcontroller"
add_consumer "METADATA_BUNDLE_PUSH" "metadata-bundle-push-gatekeeper" "deliver.metadata.bundle-push.svc-gatekeeper" "metadata-bundle-push-gatekeeper"

# METADATA_BUNDLE_PULL consumers
add_consumer "METADATA_BUNDLE_PULL" "metadata-bundle-pull-watcher" "deliver.metadata.bundle-pull.svc-watcher" "metadata-bundle-pull-watcher"
add_consumer "METADATA_BUNDLE_PULL" "metadata-bundle-pull-metadata" "deliver.metadata.bundle-pull.svc-metadata" "metadata-bundle-pull-metadata"
add_consumer "METADATA_BUNDLE_PULL" "metadata-bundle-pull-tester" "deliver.metadata.bundle-pull.svc-tester" "metadata-bundle-pull-tester"
add_consumer "METADATA_BUNDLE_PULL" "metadata-bundle-pull-authcontroller" "deliver.metadata.bundle-pull.svc-authcontroller" "metadata-bundle-pull-authcontroller"
add_consumer "METADATA_BUNDLE_PULL" "metadata-bundle-pull-gatekeeper" "deliver.metadata.bundle-pull.svc-gatekeeper" "metadata-bundle-pull-gatekeeper"

# METADATA_CLIENT consumers
# Create a per-service durable consumer for CA bundles so each service receives the CA update.
# Each consumer targets a service-specific deliver subject:
#   deliver.metadata.client.ca-cert.<service>
# and uses a durable name <service>-ca-consumer.
# Adjust CA_SERVICES list to match authorized services that should receive CA updates.
CA_SERVICES=("watcher" "authcontroller" "gatekeeper")

for svc in "${CA_SERVICES[@]}"; do
  durable="${svc}-ca-consumer"
  target="deliver.metadata.client.ca-cert.${svc}"
  echo "Creating per-service CA consumer ${durable} (target=${target}) on METADATA_CLIENT..."
  run_nats_cmd "
    if nats consumer info METADATA_CLIENT ${durable} \
      --server=tls://${NATS_SERVICE}:4222 \
      --tlscert=/etc/nats-client-tls-certs/tls.crt \
      --tlskey=/etc/nats-client-tls-certs/tls.key \
      --tlsca=/etc/nats-ca-certs/ca.crt >/dev/null 2>&1; then
      echo 'already exists'
    else
      nats consumer add METADATA_CLIENT ${durable} \
        --server=tls://${NATS_SERVICE}:4222 \
        --tlscert=/etc/nats-client-tls-certs/tls.crt \
        --tlskey=/etc/nats-client-tls-certs/tls.key \
        --tlsca=/etc/nats-ca-certs/ca.crt \
        --deliver=last \
        --target='${target}' \
        --ack=explicit \
        --flow-control \
        --heartbeat=2s \
        --max-pending=200 \
        --defaults && echo 'created' || echo 'create failed'
    fi
  "
done

# Keep request consumer used for RPC-like requests
add_consumer "METADATA_CLIENT" "metadata-client-requests" "deliver.metadata.client.request" "metadata-client-requests"

# AUTH_STREAM consumers
add_consumer "AUTH_STREAM" "auth-requests" "deliver.auth.auth-request" "auth-requests"
add_consumer "AUTH_STREAM" "auth-tester-consumer" "deliver.auth.tester.consumer" "auth-tester-consumer"

# GATEKEEPER_STREAM consumers
add_consumer "GATEKEEPER_STREAM" "gatekeeper-responder-consumer" "deliver.gatekeeper.responder" "gatekeeper-responder"

echo "=== Consumer creation complete ==="

# List all consumers for verification
echo "=== Listing all consumers ==="
for stream in METADATA_BUNDLE_PUSH METADATA_BUNDLE_PULL METADATA_CLIENT AUTH_STREAM GATEKEEPER_STREAM; do
  echo "Consumers for stream ${stream}:"
  run_nats_cmd "nats consumer list ${stream} \
    --server=tls://${NATS_SERVICE}:4222 \
    --tlscert=/etc/nats-client-tls-certs/tls.crt \
    --tlskey=/etc/nats-client-tls-certs/tls.key \
    --tlsca=/etc/nats-ca-certs/ca.crt" || true
  echo ""
done

# cleanup transient pod
kubectl --context="${CLUSTER}" delete pod -n "${NATS_NAMESPACE}" nats-client --ignore-not-found

# cleanup tmp dir
rm -rf "${TMP_CA_DIR}"

echo "STEP-06 completed: NATS deployed (StatefulSet w/ dynamic per-pod config), JetStream streams created (idempotent)."
echo "Manual: port-forward if you need to access NATS locally:"
echo "/bin/bash $PROTODIR/scripts/Helpers/Nats-portforward.sh"
read -p "Press Enter to finish..."

exit 0
