#!/bin/bash
# Run this script in a separate terminal and keep it running.
# Provides persistent port-forwarding from this machine to the in-cluster NATS service.
#
# Usage:
#   # bind to all interfaces (default)
#   ./nats-portforward.sh
#
#   # bind to specific local IP (e.g. 10.1.1.12)
#   BIND_ADDR=10.1.1.12 ./nats-portforward.sh
#
# The script will:
# - switch minikube profile to "servers" if available
# - wait for NATS pods to be running
# - start kubectl port-forward for the NATS service (ports 4222 and 8222)
# - restart the forward if it fails
#
set -euo pipefail

NAMESPACE="${NAMESPACE:-nats}"
SERVICE_NAME="${SERVICE_NAME:-nats}"
MINIKUBE_PROFILE="${MINIKUBE_PROFILE:-servers}"
BIND_ADDR="${BIND_ADDR:-0.0.0.0}"   # set to your machine IP (e.g. 10.1.1.12) if required
SLEEP_ON_FAIL="${SLEEP_ON_FAIL:-5}"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required but not found in PATH" >&2
  exit 1
fi

function minikube_profile() {
  if command -v minikube >/dev/null 2>&1; then
    minikube profile "$1" >/dev/null 2>&1 || true
  fi
}

echo "Starting persistent port-forward for NATS service '${SERVICE_NAME}' in namespace '${NAMESPACE}'"
echo "Binding forwarded ports to local address: ${BIND_ADDR}"
echo "Press Ctrl+C to stop"

# Ensure we are using the intended minikube profile (best-effort)
minikube_profile "${MINIKUBE_PROFILE}"

while true; do
  # Ensure kubecontext/profile is set (best effort)
  minikube_profile "${MINIKUBE_PROFILE}"

  # Check service exists
  if ! kubectl get svc -n "${NAMESPACE}" "${SERVICE_NAME}" >/dev/null 2>&1; then
    echo "$(date +'%Y-%m-%d %H:%M:%S') - Service '${SERVICE_NAME}' not found in namespace '${NAMESPACE}'. Waiting..."
    sleep 10
    continue
  fi

  # Check for at least one running pod for NATS
  POD_COUNT=$(kubectl get pods -n "${NAMESPACE}" -l app=nats -o jsonpath='{.items[*].status.phase}' 2>/dev/null | tr ' ' '\n' | grep -c "Running" || true)
  if [[ "${POD_COUNT}" -lt 1 ]]; then
    echo "$(date +'%Y-%m-%d %H:%M:%S') - No running NATS pods found (label=app=nats). Waiting..."
    sleep 5
    continue
  fi

  echo "$(date +'%Y-%m-%d %H:%M:%S') - Starting port forwarding to service/${SERVICE_NAME} (4222->4222, 8222->8222) bound to ${BIND_ADDR}..."

  # Run port-forward; this call blocks until it exits
  # Use explicit address flag so other-cluster access via that IP is possible.
  kubectl port-forward -n "${NAMESPACE}" svc/"${SERVICE_NAME}" 4222:4222 8222:8222 --address="${BIND_ADDR}"

  # If we get here, port-forward exited
  echo "$(date +'%Y-%m-%d %H:%M:%S') - Port-forward process exited or was interrupted. Restarting in ${SLEEP_ON_FAIL}s..."
  sleep "${SLEEP_ON_FAIL}"
done
