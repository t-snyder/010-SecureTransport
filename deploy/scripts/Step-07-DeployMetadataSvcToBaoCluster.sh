#!/bin/bash

##########################################################################################
# Updated to work with NATS JetStream instead of Pulsar
# Manual deployment instructions:
# 1. Set HOST_IP to your local IP accessible from the cluster (e.g. 10.1.1.12)
# 2. Make sure minikube tunnel or port-forward is running for Vault and NATS
# 3. Run this script with the correct PROTODIR and SCHEMADIR
# 4. Use 'kubectl get pods -n metadata' to verify pod status
##########################################################################################

# Prompt for local host IP if not set -- Used for NATS connection
if [[ -z "$HOST_IP" ]]; then
  read -p "Enter the local host IP accessible from minikube (e.g., 10.1.1.12): " HOST_IP
fi

# Project directory path - change as needed
PROTODIR=${PROTODIR:-/media/tim/ExtraDrive1/Projects/009-SecureKeyAndCertRotation/deploy}
SCHEMADIR=${SCHEMADIR:-/media/tim/ExtraDrive1/Projects/009-SecureKeyAndCertRotation/svc-core/src/main/resources/avro}
NAMESPACE="metadata"
CA_CERT_PATH="/openbao/userconfig/openbao-tls/openbao.ca"

# Minikube profiles
MINIKUBE_BAO_PROFILE="bao"

##########################################################################################
# Get Vault Role ID and Secret ID
minikube profile $MINIKUBE_BAO_PROFILE

kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

ROLE_ID=$(kubectl exec -i -n openbao openbao-0 -- bao read -ca-cert=$CA_CERT_PATH -field=role_id auth/approle/role/metadata/role-id | tr -d '\r\n')
if [ -z "$ROLE_ID" ]; then
    echo "Failed to retrieve ROLE_ID"
    exit 1
fi

SECRET_ID=$(kubectl exec -i -n openbao openbao-0 -- bao write -ca-cert=$CA_CERT_PATH -field=secret_id -f auth/approle/role/metadata/secret-id | tr -d '\r\n')
if [ -z "$SECRET_ID" ]; then
    echo "Failed to retrieve SECRET_ID"
    exit 1
fi

echo "Role ID: $ROLE_ID"
echo "Secret ID: $SECRET_ID"

# Create Kubernetes secrets for OpenBao AppRole
kubectl create secret generic metadata-bao-approle \
        --from-literal=role-id="$ROLE_ID" \
        --from-literal=secret-id="$SECRET_ID" \
        --namespace=$NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# Create Auth for OpenBao Secrets Operator
kubectl apply -f- <<EOF
apiVersion: secrets.openbao.org/v1beta1
kind: VaultAuth
metadata:
  name: metadata-service-auth
  namespace: metadata
spec:
  method: approle
  mount: approle
  appRole:
    roleId: "$ROLE_ID"
    secretRef:
      name: metadata-bao-approle
      key: secret-id
EOF

# Create NATS CA secret (using same pulsar_int intermediate CA)
NATS_CA="$PROTODIR/openbao/gen/crypto/pulsar_ca_bundle.pem"
kubectl create secret generic nats-ca-secret \
        --from-file=ca.crt="$NATS_CA" \
        --namespace=$NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# Create OpenBao CA secret
BAO_CLIENT_CA_BUNDLE="$PROTODIR/openbao/gen/crypto/openbao.ca"
kubectl create secret generic openbao-ca-secret \
        --from-file=ca.crt="$BAO_CLIENT_CA_BUNDLE" \
        --namespace=$NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

HOST_IP=$(hostname -I | cut -f1 -d' ')
BAO_ADDR="https://openbao.openbao.svc.cluster.local:8200"

# Deploy the metadata-tls-issuer for cert-manager
kubectl apply -f- <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: metadata-tls-issuer
  namespace: $NAMESPACE
spec:
  vault:
    path: pulsar_int/sign/metadata-tls-issuer
    server: $BAO_ADDR
    caBundle: $(base64 -w0 < "$BAO_CLIENT_CA_BUNDLE")
    auth:
      appRole:
        path: approle
        roleId: $ROLE_ID
        secretRef:
          name: metadata-bao-approle
          key: secret-id
EOF

# Create metadata service NATS client certificate for authentication and authorization
kubectl apply -f- <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: metadata-nats-client-tls
  namespace: $NAMESPACE
spec:
  secretName: metadata-nats-client-tls
  issuerRef:
    name: metadata-tls-issuer
    kind: Issuer
  dnsNames:
  - metadata-service
  - metadata-service.metadata.svc.cluster.local
  duration: 12h
  renewBefore: 2h
  keySize: 4096
  keyAlgorithm: rsa
EOF

# Wait for certificate
kubectl wait --for=condition=ready certificate/metadata-nats-client-tls -n $NAMESPACE --timeout=300s

# Build the metadata-svc microservice image
/bin/bash $PROTODIR/scripts/buildMetadataImage.sh

# Create avro-schemas configmap
kubectl create -n metadata configmap avro-schemas --from-file=$SCHEMADIR/ --dry-run=client -o yaml | kubectl apply -f -

# Create metadata configuration for NATS instead of Pulsar
NATS_URL="tls://$HOST_IP:4222"

# Create updated metadata config for NATS
kubectl create configmap metadata-configmap \
  --from-literal=messaging.url="$NATS_URL" \
  --from-literal=messaging.type="nats" \
  --from-literal=messaging.tls.enabled="true" \
  --from-literal=messaging.tls.cert="/etc/nats-client-tls-certs/tls.crt" \
  --from-literal=messaging.tls.key="/etc/nats-client-tls-certs/tls.key" \
  --from-literal=messaging.tls.ca="/etc/nats-ca-certs/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -n metadata -f -

kubectl -n metadata apply -f $PROTODIR/kube-metadata/bao-agent-configmap.yaml

kubectl -n metadata apply -f $PROTODIR/kube-metadata/metadata-pvc.yaml
kubectl -n metadata apply -f $PROTODIR/kube-metadata/metadata-sa.yaml
kubectl -n metadata apply -f $PROTODIR/kube-metadata/metadata-rbac.yaml

# Deploy metadata service with NATS configuration
kubectl apply -f- <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: metadata-service
  namespace: metadata
spec:
  replicas: 1
  selector:
    matchLabels:
      app: metadata-service
  template:
    metadata:
      labels:
        app: metadata-service
    spec:
      serviceAccountName: metadata-service-account
      containers:
      - name: metadata-service
        image: metadata-svc:latest
        imagePullPolicy: Never
        ports:
        - containerPort: 8080
        env:
        - name: NATS_URL
          valueFrom:
            configMapKeyRef:
              name: metadata-configmap
              key: messaging.url
        - name: VAULT_ADDR
          value: "https://openbao.openbao.svc.cluster.local:8200"
        - name: VAULT_ROLE_ID
          valueFrom:
            secretKeyRef:
              name: metadata-bao-approle
              key: role-id
        - name: VAULT_SECRET_ID
          valueFrom:
            secretKeyRef:
              name: metadata-bao-approle
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
        - name: data
          mountPath: /data
      volumes:
      - name: nats-client-tls-certs
        secret:
          secretName: metadata-nats-client-tls
      - name: nats-ca-certs
        secret:
          secretName: nats-ca-secret
      - name: openbao-ca-certs
        secret:
          secretName: openbao-ca-secret
      - name: avro-schemas
        configMap:
          name: avro-schemas
      - name: data
        persistentVolumeClaim:
          claimName: metadata-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: metadata-service
  namespace: metadata
spec:
  selector:
    app: metadata-service
  ports:
  - port: 8080
    targetPort: 8080
  type: ClusterIP
EOF

# Set both namespaces as part of the istio ambient mesh and force mtls between all pods 
# within those namespaces.
kubectl label namespace metadata istio.io/dataplane-mode=ambient
kubectl label namespace openbao  istio.io/dataplane-mode=ambient

##########################################################################################
# Final instructions for manual steps
##########################################################################################
echo ""
echo "============================================================================="
echo "Deployment complete."
echo ""
echo ">> IMPORTANT: Make sure the port forward is running in a separate terminal for:"
echo "   - OpenBao: port 8200"  
echo "   - NATS: port 4222"
echo ""
echo "✓ NATS JetStream provides hot certificate reload"
echo "✓ Certificate rotation downtime: 1-2 seconds (vs 30-45 with Pulsar)"
echo "✓ Metadata service configured for NATS messaging"
echo "============================================================================="
