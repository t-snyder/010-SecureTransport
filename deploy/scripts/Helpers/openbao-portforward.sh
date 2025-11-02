#!/bin/bash
# Run this script in a separate terminal window and keep it running

echo "Starting persistent port-forward for OpenBao ..."
echo "Press Ctrl+C to stop"

while true; do

  # Start port-forwarding
  echo "$(date +'%Y-%m-%d %H:%M:%S') - Starting port forwarding..."
  minikube profile bao
  kubectl -n openbao port-forward service/openbao 8200:8200 --address 0.0.0.0
  
  # If we get here, port-forwarding failed
  echo "$(date +'%Y-%m-%d %H:%M:%S') - Port forwarding interrupted. Restarting in 5 seconds..."
  sleep 5
done
