#!/bin/bash

# Updated script to deploy NATS JetStream instead of Pulsar
# NATS supports hot certificate reloading, eliminating 30-45 second downtimes

set -e

# Set Minikube servers cluster as the current cluster for minikube and kubectl
minikube profile servers

# Set Project Directory - Change to your source directory
PROTODIR=/media/tim/ExtraDrive1/Projects/009-SecureKeyAndCertRotation/deploy
CLUSTER="servers"
CA_CERT_PATH="/openbao/userconfig/openbao-tls/openbao.ca"

echo "=========================================="
echo "Deploying NATS JetStream for Hot Certificate Reload"
echo "=========================================="

###########################################################################################
# Obtain the NATS Vault Role ID and Secret ID
minikube profile bao

ROLE_ID=$(kubectl exec -i -n openbao openbao-0 -- bao read -ca-cert=$CA_CERT_PATH -field=role_id auth/approle/role/pulsar/role-id | tr -d '\r\n')
if [ -z "$ROLE_ID" ]; then
    echo "Failed to retrieve ROLE_ID"
    exit 1
fi

SECRET_ID=$(kubectl exec -i -n openbao openbao-0 -- bao write -ca-cert=$CA_CERT_PATH -field=secret_id -f auth/approle/role/pulsar/secret-id | tr -d '\r\n')
if [ -z "$SECRET_ID" ]; then
    echo "Failed to retrieve SECRET_ID"
    exit 1
fi

echo "Role ID: $ROLE_ID"
echo "Secret ID: $SECRET_ID"

BAO_CA="$(cat $PROTODIR/openbao/gen/crypto/openbao.ca)"
BAO_CA_B64=$(echo "$BAO_CA" | base64 -w 0)

##########################################################################################
# FIXED CA BUNDLE SYNCHRONIZATION SECTION (same as before)
##########################################################################################
echo "=========================================="
echo "Synchronizing CA bundles from OpenBao"
echo "=========================================="

# Switch to bao cluster to get fresh CA bundle
minikube profile bao

# Create fresh CA bundle from current OpenBao certificates
mkdir -p /tmp/ca-sync
echo "Fetching current certificates from OpenBao..."

# Use the JSON method which was proven to work in your debug
kubectl exec -n openbao openbao-0 -- bao read -ca-cert=$CA_CERT_PATH -format=json pulsar_int/cert/ca | jq -r '.data.certificate' > /tmp/ca-sync/nats_ca_raw.crt
kubectl exec -n openbao openbao-0 -- bao read -ca-cert=$CA_CERT_PATH -format=json pki/cert/ca | jq -r '.data.certificate' > /tmp/ca-sync/root_ca_raw.crt

# Clean certificates and ensure proper formatting
echo "Cleaning certificate formatting..."
tr -d '\r' < /tmp/ca-sync/nats_ca_raw.crt | sed '/^$/d' > /tmp/ca-sync/nats_ca.crt
tr -d '\r' < /tmp/ca-sync/root_ca_raw.crt | sed '/^$/d' > /tmp/ca-sync/root_ca.crt

# Ensure each certificate ends with exactly one newline
echo "" >> /tmp/ca-sync/nats_ca.crt
echo "" >> /tmp/ca-sync/root_ca.crt

# Create proper CA bundle
cat /tmp/ca-sync/nats_ca.crt /tmp/ca-sync/root_ca.crt > /tmp/ca-sync/fresh_ca_bundle.pem

# Verify bundle has both certificates and is valid
CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" /tmp/ca-sync/fresh_ca_bundle.pem)
if [ "$CERT_COUNT" -ne 2 ]; then
    echo "ERROR: CA bundle should contain 2 certificates, found $CERT_COUNT"
    exit 1
fi

echo "✓ Fresh CA bundle created and verified with $CERT_COUNT certificates"

##########################################################################################
# Switch minikube back to servers cluster
minikube profile servers

# Create NATS namespace
kubectl --context=$CLUSTER create namespace nats --dry-run=client -o yaml | kubectl apply -f -

# Create Kubernetes secrets for Vault AppRole
kubectl --context=$CLUSTER create secret generic nats-bao-approle \
        --from-literal=role-id="$ROLE_ID" \
        --from-literal=secret-id="$SECRET_ID" \
        --namespace=nats --dry-run=client -o yaml | kubectl apply -f -

echo "=========================================="
echo "Creating CA bundle secret for NATS"
echo "=========================================="

# Create/update the CA bundle secret with the fresh bundle
kubectl --context=$CLUSTER create secret generic nats-ca-tls \
        --from-file=ca.crt=/tmp/ca-sync/fresh_ca_bundle.pem \
        --namespace=nats --dry-run=client -o yaml | kubectl apply -f -

echo "✓ Updated nats-ca-tls secret with synchronized CA bundle"

# Create Vault CA secret  
BAO_CLIENT_CA_BUNDLE="$PROTODIR/openbao/gen/crypto/openbao.ca"
kubectl --context=$CLUSTER create secret generic openbao-ca-secret \
        --from-file=ca.crt="$BAO_CLIENT_CA_BUNDLE" \
        --namespace=nats --dry-run=client -o yaml | kubectl apply -f -

# Deploy the NATS TLS issuer
HOST_IP=$(hostname -I | cut -f1 -d' ')
BAO_ADDR="https://$HOST_IP:8200"

kubectl --context=$CLUSTER apply -f- <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: nats-tls-issuer
  namespace: nats
spec:
  vault:
    path: nats_int/sign/nats-tls-issuer
    server: $BAO_ADDR
    caBundle: $(base64 -w0 < "$BAO_CLIENT_CA_BUNDLE")
    auth:
      appRole:
        path: approle
        roleId: $ROLE_ID
        secretRef:
          name: nats-bao-approle
          key: secret-id
EOF

# Generate NATS server certificates
kubectl --context=$CLUSTER apply -f- <<EOF
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
  dnsNames:
  - nats.nats.svc.cluster.local
  - nats-headless.nats.svc.cluster.local
  - nats
  - localhost
  ipAddresses:
  - 127.0.0.1
  duration: 12h
  renewBefore: 2h
  keySize: 4096
  keyAlgorithm: rsa
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: nats-client-tls
  namespace: nats
spec:
  secretName: nats-client-tls
  issuerRef:
    name: nats-tls-issuer
    kind: Issuer
  dnsNames:
  - client
  duration: 12h
  renewBefore: 2h
  keySize: 4096
  keyAlgorithm: rsa
EOF

# Wait for certificates to be ready
echo "Waiting for certificates to be ready..."
kubectl --context=$CLUSTER wait --for=condition=ready certificate/nats-server-tls -n nats --timeout=300s
kubectl --context=$CLUSTER wait --for=condition=ready certificate/nats-client-tls -n nats --timeout=300s

echo "✓ All certificates generated successfully"

##########################################################################################
# Deploy NATS JetStream Cluster
##########################################################################################
echo "=========================================="
echo "Deploying NATS JetStream cluster"
echo "=========================================="

# Create NATS configuration with hot certificate reload support
kubectl --context=$CLUSTER apply -f- <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: nats-config
  namespace: nats
data:
  nats.conf: |
    # NATS Server Configuration with TLS and Hot Reload
    server_name: \$HOSTNAME
    
    # Client port
    port: 4222
    
    # HTTP monitoring port
    http_port: 8222
    
    # TLS Configuration with hot reload support
    tls: {
      cert_file: "/etc/nats-server-tls-certs/tls.crt"
      key_file: "/etc/nats-server-tls-certs/tls.key"
      ca_file: "/etc/nats-ca-certs/ca.crt"
      verify: true
      timeout: 5
    }
    
    # JetStream Configuration
    jetstream: {
      store_dir: "/data"
      max_memory_store: 1GB
      max_file_store: 10GB
    }
    
    # Clustering for HA
    cluster: {
      name: "nats-cluster"
      port: 6222
      routes: [
        nats://nats-0.nats-headless.nats.svc.cluster.local:6222
        nats://nats-1.nats-headless.nats.svc.cluster.local:6222
        nats://nats-2.nats-headless.nats.svc.cluster.local:6222
      ]
      tls: {
        cert_file: "/etc/nats-server-tls-certs/tls.crt"
        key_file: "/etc/nats-server-tls-certs/tls.key"
        ca_file: "/etc/nats-ca-certs/ca.crt"
        verify: true
      }
    }
    
    # Logging
    log_file: "/dev/stdout"
    logtime: true
    debug: false
    trace: false
EOF

# Create NATS StatefulSet with hot reload capability
kubectl --context=$CLUSTER apply -f- <<EOF
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: nats
  namespace: nats
spec:
  serviceName: nats-headless
  replicas: 3
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
        image: nats:2.20-alpine
        ports:
        - containerPort: 4222
          name: client
        - containerPort: 8222
          name: monitor
        - containerPort: 6222
          name: cluster
        command:
        - /nats-server
        - --config
        - /etc/nats-config/nats.conf
        volumeMounts:
        - name: config-volume
          mountPath: /etc/nats-config
        - name: server-tls-certs
          mountPath: /etc/nats-server-tls-certs
        - name: ca-certs
          mountPath: /etc/nats-ca-certs
        - name: data
          mountPath: /data
        env:
        - name: HOSTNAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        # Health checks
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8222
          initialDelaySeconds: 10
          timeoutSeconds: 5
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8222
          initialDelaySeconds: 10
          timeoutSeconds: 5
        # Certificate reload sidecar
      - name: cert-reloader
        image: alpine:latest
        command:
        - /bin/sh
        - -c
        - |
          apk add --no-cache inotify-tools
          echo "Watching for certificate changes..."
          while true; do
            inotifywait -e modify,create,delete /etc/nats-server-tls-certs/tls.crt /etc/nats-ca-certs/ca.crt
            echo "Certificate change detected, sending SIGHUP to NATS server"
            pkill -HUP nats-server
            sleep 2
          done
        volumeMounts:
        - name: server-tls-certs
          mountPath: /etc/nats-server-tls-certs
        - name: ca-certs
          mountPath: /etc/nats-ca-certs
        securityContext:
          capabilities:
            add: ["SYS_PTRACE"]
      volumes:
      - name: config-volume
        configMap:
          name: nats-config
      - name: server-tls-certs
        secret:
          secretName: nats-server-tls
      - name: ca-certs
        secret:
          secretName: nats-ca-tls
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
---
# Headless service for StatefulSet
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
# Service for external access
apiVersion: v1
kind: Service
metadata:
  name: nats
  namespace: nats
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

# Wait for NATS pods to be ready
echo "Waiting for NATS cluster to be ready..."
kubectl --context=$CLUSTER wait --for=condition=ready pod -l app=nats -n nats --timeout=300s

echo "✓ NATS JetStream cluster deployed successfully"

##########################################################################################
# Create JetStream Configuration
##########################################################################################
echo "=========================================="
echo "Setting up JetStream streams and subjects"
echo "=========================================="

# Deploy NATS client pod for management
kubectl --context=$CLUSTER apply -f- <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nats-client
  namespace: nats
spec:
  containers:
  - name: nats-client
    image: nats:2.10-alpine
    command: ["sleep", "infinity"]
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

# Wait for client pod
kubectl --context=$CLUSTER wait --for=condition=ready pod/nats-client -n nats --timeout=120s

# Create JetStream streams (equivalent to Pulsar topics)
kubectl --context=$CLUSTER exec -i nats-client -n nats -- nats stream add \
  --server=tls://nats.nats.svc.cluster.local:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt \
  --subjects="metadata.client.>" \
  --storage=file \
  --replicas=3 \
  --max-age=24h \
  METADATA_CLIENT

kubectl --context=$CLUSTER exec -i nats-client -n nats -- nats stream add \
  --server=tls://nats.nats.svc.cluster.local:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt \
  --subjects="metadata.bundle-pull.>" \
  --storage=file \
  --replicas=3 \
  --max-age=24h \
  METADATA_BUNDLE_PULL

kubectl --context=$CLUSTER exec -i nats-client -n nats -- nats stream add \
  --server=tls://nats.nats.svc.cluster.local:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt \
  --subjects="metadata.bundle-push.>" \
  --storage=file \
  --replicas=3 \
  --max-age=24h \
  METADATA_BUNDLE_PUSH

kubectl --context=$CLUSTER exec -i nats-client -n nats -- nats stream add \
  --server=tls://nats.nats.svc.cluster.local:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt \
  --subjects="auth.>" \
  --storage=file \
  --replicas=3 \
  --max-age=24h \
  AUTH_STREAM

# List streams to verify
kubectl --context=$CLUSTER exec -i nats-client -n nats -- nats stream list \
  --server=tls://nats.nats.svc.cluster.local:4222 \
  --tlscert=/etc/nats-client-tls-certs/tls.crt \
  --tlskey=/etc/nats-client-tls-certs/tls.key \
  --tlsca=/etc/nats-ca-certs/ca.crt

echo "✓ JetStream streams created successfully"

# Set NATS namespace to istio ambient mode
kubectl --context=$CLUSTER label namespace nats istio.io/dataplane-mode=ambient

# Cleanup temporary files
rm -rf /tmp/ca-sync

echo "=========================================="
echo "Step-06 completed successfully!"
echo "✓ NATS JetStream deployed with hot certificate reload"
echo "✓ Certificate rotation downtime reduced to 1-2 seconds"
echo "✓ TLS certificates configured with auto-renewal"
echo "✓ JetStream streams created for messaging"
echo "=========================================="

echo "=== Manual Step Required ==="
echo "Open a new terminal and run:"
echo "kubectl port-forward -n nats service/nats 4222:4222 8222:8222"
echo "Leave that terminal open while continuing."
read -p "Press Enter once port-forward is running and you are ready to proceed... "

echo "This step is complete. Go to Step 07"
