#!/bin/bash

# Step 1 - Deploys and configures the following:
#            a) minikube, minikube addons (dashboard, metallb (Load Balancer));
#            b) configures load balancer ip address range

# This learning prototype was developed and tested using the following:
#   a) Ubuntu             - 20.04.6 LTS
#   b) Minikube           - 1.35.0
#   c) Kubernetes         - 1.31.0
#   d) Docker             - 27.2.0
#   d) Cert-manager       - 1.17.5
#   e) Istio              - 1.26.1
#   e) Hashicorp Vault    - 1.19.5
#   f) Kubernetes Gateway - 1.2.0
#   g) OpenSSL            - 3.4.0
#
# Laptop Machine configuration:
#     - Processor - Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 
#       Memory    - 64 GB
# 
# Open terminal 1
# Record Start time
current_date_time=$(date)
echo "Current date and time: $current_date_time"
CLUSTER="bao"

# Delete prior minikube ( if used and configured prior)
minikube delete -p $CLUSTER

# Start minikube - configure the settings to your requirements and hardware
# Note - normally I use kvm2 as the vm-driver. However istio cni in ambient mode does not
# currently work with kvm2 due to cni incompatibility. The work around is to use the 
# docker vm-driver.
minikube start -p $CLUSTER --cpus 3 --memory 6144 --vm-driver docker --cni kindnet --disk-size 100g 

# Set minikube commands to use vault cluster
minikube profile $CLUSTER

# Addons
minikube addons enable -p $CLUSTER dashboard

# Deploy the addon loadbalancer metallb
minikube addons enable -p $CLUSTER metallb

# Configure loadbalancer ip address range within the same range as the minikube ip
# The configuration is a start ip ( ie. 192.168.49.20 ) and an end ip that makes a 
# range of 10 ip addresses. The range should not overlap the minikube ip
minikube -p $CLUSTER ip
minikube addons configure -p $CLUSTER metallb

# Start dashboard
minikube -p $CLUSTER dashboard &

############## Open up a new (2nd) terminal ###################################
# Install the Kubernetes Gateway API CRDs (experimental also includes standard)
kubectl --context=$CLUSTER apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/experimental-install.yaml

# Wait for critical Gateway API CRDs to be established
echo "Waiting for Gateway API CRDs to be ready..."
until kubectl --context=$CLUSTER get crd gateways.gateway.networking.k8s.io &>/dev/null; do 
  sleep 2
  echo "Waiting for gateway CRDs to be established..."
done
echo "Gateway API CRDs are ready."

# Install istio in ambient mode
istioctl --context=$CLUSTER install --set values.pilot.env.PILOT_ENABLE_ALPHA_GATEWAY_API=true --set profile=ambient --skip-confirmation

#### Install cert-manager with the following steps ####
# Create cert-manger namespace
kubectl --context=$CLUSTER create namespace cert-manager

# Deploy cert-manager gateway CRDs
CERT_MANAGER_VERSION="v1.17.3"
           
kubectl --context=$CLUSTER apply -f https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.crds.yaml

# Deploy cert-manager with gateway api enabled including the experimental gateway apis
#helm --context=$CLUSTER install cert-manager jetstack/cert-manager \
#  --namespace cert-manager \
#  --version ${CERT_MANAGER_VERSION} \
#  --set config.apiVersion="controller.config.cert-manager.io/v1alpha1" \
#  --set config.kind="ControllerConfiguration" \
#  --set config.enableGatewayAPI=true \
#  --set "extraArgs={--feature-gates=ExperimentalGatewayAPISupport=true}"

helm install cert-manager jetstack/cert-manager \
  --kube-context "$CLUSTER" \
  --namespace cert-manager \
  --create-namespace \
  --version "${CERT_MANAGER_VERSION}" \
  --set installCRDs=false \
  --set extraArgs[0]="--feature-gates=ExperimentalGatewayAPISupport=true" \
  --set config.enableGatewayAPI=true  
  
# Create the vault namespace
kubectl --context=$CLUSTER create namespace openbao

# Vault setup Step 04 - has a dependency on the Pulsar cluster being up cert-manager and pulsar namespace
# Next step in vault setup is Step 2 - setup the TLS configuration for Vault and deploy vault.

