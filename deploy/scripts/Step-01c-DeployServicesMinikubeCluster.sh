#!/bin/bash

# The following scripting is based upon a Pulsar tutorial for running Pulsar in Kubernetes on
# minikube. The url for the tuturial is:
# https://pulsar.apache.org/docs/4.0.x/getting-started-helm/

# Step 1 - Deploys and configures the following:
#            a) Deploys a fresh minikube with minikube addons (dashboard, metallb);
#            c) Configures Metallb loadbalancer
#            d) Deploys Kubernetes Gateway API CRDs (cert-manager deploy uses)
#            e) Deploys istio in Ambient mode.
#            f) Deploys Cert-Manager
#            g) Deploys Pulsar and all required components into the Cluster
#            h) Sets pulsar namespace to istio ambient mode which initiates mTLS between pods
#            f) Tests access from the Pulsar CLI client
#            g) Allows running of the simple java test program (eclipse, maven) found in the
#               pulsar-client directory within this project.

# This learning prototypes were developed and tested using the following:
#   a) Ubuntu                 - 20.04.6 LTS
#   b) Minikube               - 1.36.0
#   c) Kubernetes             - 1.33.1
#   d) Docker                 - 28.1.1
#   e) Metallb                - 0.9.6
#   f) Kubernetes Gateway API - 1.2.0
#   g) Istio (Ambient Mode)   - 1.23.2
#   h) Cert-Manager           - 1.15.5
#   i) Machine config - Processor - Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 
#                       Memory    - 64 GB
# 
###########################################################################################         
# Open a new terminal 3

CLUSTER="services"

# Delete prior minikube ( if used and configured prior)
minikube delete -p $CLUSTER

# Start minikube - configure the settings to your requirements and hardware
# Note - normally I use kvm2 as the vm-driver. However istio cni in ambient mode does not
# currently work with kvm2 due to cni incompatibility. The work around is to use the 
# docker vm-driver.
minikube start -p $CLUSTER --cpus 2 --memory 12288 --vm-driver docker --cni kindnet --disk-size 100g

# configures kubectl to the servers instance.
#minikube profile services

# Addons
minikube -p $CLUSTER addons enable dashboard

# Deploy the addon loadbalancer metallb
minikube -p $CLUSTER addons enable metallb

# Configure loadbalancer ip address range within the same range as the minikube ip
# The configuration is a start ip ( ie. 192.168.49.20 ) and an end ip that makes a 
# range of 5-10 ip addresses. The range should not overlap the minikube ip
minikube -p $CLUSTER ip
minikube -p $CLUSTER addons configure metallb

# Start dashboard
minikube -p $CLUSTER dashboard &

############## Open up a new terminal ###################################
CERT_MANAGER_VERSION="v1.17.3"

# Install the Kubernetes Gateway API CRDs (experimental also includes standard)
kubectl --context=$CLUSTER apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/experimental-install.yaml

# Install istio in ambient mode
istioctl --context=$CLUSTER install --set values.pilot.env.PILOT_ENABLE_ALPHA_GATEWAY_API=true --set profile=ambient --skip-confirmation

#### Install cert-manager with the following steps ####
# Create cert-manger namespace
kubectl --context=$CLUSTER create namespace cert-manager

# Deploy cert-manager gateway CRDs
kubectl --context=$CLUSTER apply -f https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.crds.yaml

# Deploy cert-manager with gateway api enabled including the experimental gateway apis
echo "Installing cert-manager on $CLUSTER"
helm install cert-manager jetstack/cert-manager \
  --kube-context "$CLUSTER" \
  --namespace cert-manager \
  --create-namespace \
  --version "${CERT_MANAGER_VERSION}" \
  --set installCRDs=false \
  --set extraArgs[0]="--feature-gates=ExperimentalGatewayAPISupport=true" \
  --set config.enableGatewayAPI=true
  
 

