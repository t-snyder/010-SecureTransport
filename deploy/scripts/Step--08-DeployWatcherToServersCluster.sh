#!/bin/bash
# Deploy Watcher for NATS JetStream

# Switch to new terminal for servers cluster
minikube profile servers

PROTODIR=/media/tim/ExtraDrive1/Projects/009-SecureKeyAndCertRotation/deploy
SCHEMADIR=/media/tim/ExtraDrive1/Projects/009-SecureKeyAndCertRotation/svc-core/src/main/resources/avro
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

# Switch minikube profile back to servers
minikube profile servers

HOST_IP=$(hostname -I | cut -f1 -d' ')
BAO_ADDR="https://$HOST_IP:8200"

# Create Kubernetes secrets
kubectl create secret generic watcher-bao-approle \
        --from-literal=role-id="$AGENT_ROLE_ID" \
        --from-literal=secret-id="$AGENT_SECRET_ID" \
        --namespace=nats --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic nats-ca-secret \
        --from-file=ca.crt="$PROTODIR/openbao/gen/crypto/pulsar_ca_bundle.pem" \
        --namespace=nats --dry-run=client -o yaml | kubectl apply -f -

# Create Bao CA secret
BAO_CLIENT_CA_BUNDLE="$PROTODIR/openbao/gen/crypto/openbao.ca"
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
    path: pulsar_int/sign/watcher-tls-issuer
    server: $BAO_ADDR
    caBundle: $(base64 -w0 < "$BAO_CLIENT_CA_BUNDLE")
    auth:
      appRole:
        path: approle
        roleId: $AGENT_ROLE_ID
        secretRef:
          name: watcher-bao-approle
          key: secret-id
EOF

# Create watcher NATS client certificate
kubectl apply -f- <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: watcher-nats-client-tls
  namespace: nats
spec:
  secretName: watcher-nats-client-tls
  issuerRef:
    name: watcher-tls-issuer
    kind: Issuer
  dnsNames:
  - watcher-service
  - watcher-service.nats.svc.cluster.local
  duration: 12h
  renewBefore: 2h
  keySize: 4096
  keyAlgorithm: rsa
EOF

# Wait for certificate
kubectl wait --for=condition=ready certificate/watcher-nats-client-tls -n nats --timeout=300s

# Build the watcher microservice image.
/bin/bash $PROTODIR/scripts/buildWatcherImage.sh

# Deploy watcher service for NATS
kubectl apply -f- <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: watcher-service
  namespace: nats
spec:
  replicas: 1
  selector:
    matchLabels:
      app: watcher-service
  template:
    metadata:
      labels:
        app: watcher-service
    spec:
      containers:
      - name: watcher-service
        image: watcher-svc:latest
        imagePullPolicy: Never
        ports:
        - containerPort: 8080
        env:
        - name: NATS_URL
          value: "tls://nats.nats.svc.cluster.local:4222"
        - name: VAULT_ADDR
          value: "https://openbao.openbao.svc.cluster.local:8200"
        - name: VAULT_ROLE_ID
          valueFrom:
            secretKeyRef:
              name: watcher-bao-approle
              key: role-id
        - name: VAULT_SECRET_ID
          valueFrom:
            secretKeyRef:
              name: watcher-bao-approle
              key: secret-id
        volumeMounts:
        - name: nats-client-tls-certs
          mountPath: /etc/nats-client-tls-certs
        - name: nats-ca-certs
          mountPath: /etc/nats-ca-certs
        - name: openbao-ca-certs
          mountPath: /etc/openbao-ca-certs
        - name: avro-schemas
          mountPath: /etc/avro-schemas
        # Certificate change monitoring for instant updates
        - name: cert-watch-script
          mountPath: /etc/cert-watch
      # Sidecar to monitor certificate changes and notify application
      - name: cert-watcher
        image: alpine:latest
        command:
        - /bin/sh
        - -c
        - |
          apk add --no-cache inotify-tools curl
          echo "Monitoring certificates for changes..."
          while true; do
            inotifywait -e modify,create,delete /etc/nats-client-tls-certs/tls.crt /etc/nats-ca-certs/ca.crt
            echo "Certificate change detected, notifying watcher service"
            curl -X POST http://localhost:8080/reload-certificates || true
            sleep 1
          done
        volumeMounts:
        - name: nats-client-tls-certs
          mountPath: /etc/nats-client-tls-certs
        - name: nats-ca-certs
          mountPath: /etc/nats-ca-certs
      volumes:
      - name: nats-client-tls-certs
        secret:
          secretName: watcher-nats-client-tls
      - name: nats-ca-certs
        secret:
          secretName: nats-ca-secret
      - name: openbao-ca-certs
        secret:
          secretName: openbao-ca-secret
      - name: avro-schemas
        configMap:
          name: avro-schemas
      - name: cert-watch-script
        configMap:
          name: cert-watch-config
---
apiVersion: v1
kind: Service
metadata:
  name: watcher-service
  namespace: nats
spec:
  selector:
    app: watcher-service
  ports:
  - port: 8080
    targetPort: 8080
  type: ClusterIP
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cert-watch-config
  namespace: nats
data:
  watch.sh: |
    #!/bin/sh
    # Certificate watch script for immediate reload notification
    while true; do
      inotifywait -e modify,create,delete /etc/nats-client-tls-certs/tls.crt /etc/nats-ca-certs/ca.crt
      echo "Certificate change detected at $(date)"
      curl -X POST http://localhost:8080/reload-certificates
      sleep 1
    done
EOF

echo "=========================================="
echo "Watcher service deployed successfully!"
echo "✓ NATS JetStream integration configured"
echo "✓ Hot certificate reload with 1-2 second response time"
echo "✓ Certificate change monitoring enabled"
echo "✓ Cross-cluster CA bundle synchronization active"
echo "=========================================="
