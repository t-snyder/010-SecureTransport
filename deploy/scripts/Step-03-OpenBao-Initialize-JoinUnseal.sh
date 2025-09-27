#!/bin/bash

# OpenBao internal setup commands - join, unseal
# Adapted from Vault Minikube HA TLS guide, for OpenBao

set -e  # Exit immediately if a command exits with a non-zero status

NAMESPACE="openbao"
PROTODIR=/media/tim/ExtraDrive1/Projects/009-SecureKeyAndCertRotation/deploy
CA_CERT_PATH="/openbao/userconfig/openbao-tls/openbao.ca"
CLIENT_CERT_PATH="/openbao/userconfig/openbao-tls/openbao.crt"
CLIENT_KEY_PATH="/openbao/userconfig/openbao-tls/openbao.key"

wait_for_openbao() {
    echo "Waiting for openbao-0 to be up and ready..."
    while true; do
        if kubectl -n $NAMESPACE get pods | grep -q "openbao-0.*Running"; then
            echo "openbao-0 is up and ready."
            break
        else
            echo "openbao-0 is not ready yet. Waiting..."
            sleep 10
        fi
    done
}

initialize_openbao() {
    echo "Initializing openbao-0..."
    kubectl exec -n openbao openbao-0 -- bao operator init \
        -key-shares=1 \
        -key-threshold=1 \
        -format=json \
        -ca-cert=$CA_CERT_PATH \
        -client-cert=$CLIENT_CERT_PATH \
        -client-key=$CLIENT_KEY_PATH \
        > ${PROTODIR}/openbao/gen/crypto/cluster-keys.json

    echo "Unseal key:"
    jq -r ".unseal_keys_b64[]" ${PROTODIR}/openbao/gen/crypto/cluster-keys.json
}


unseal_openbao() {
    local unseal_key=$(jq -r ".unseal_keys_b64[]" ${PROTODIR}/openbao/gen/crypto/cluster-keys.json)
    echo "Unsealing openbao-0..."
    kubectl exec -n openbao openbao-0 -- bao operator unseal \
        -ca-cert=$CA_CERT_PATH \
        -client-cert=$CLIENT_CERT_PATH \
        -client-key=$CLIENT_KEY_PATH \
        $unseal_key
}

join_openbao_node() {
    local node_name=$1
    echo "Joining $node_name to raft cluster..."
    kubectl exec -n $NAMESPACE $node_name -- /bin/sh -c "
      bao operator raft join \
        -ca-cert=$CA_CERT_PATH \
        -address=https://$node_name.openbao-internal:8200 \
        -leader-ca-cert=\"\$(cat $CA_CERT_PATH)\" \
        -leader-client-cert=\"\$(cat $CLIENT_CERT_PATH)\" \
        -leader-client-key=\"\$(cat $CLIENT_KEY_PATH)\" \
        https://openbao-0.openbao-internal:8200
    "
}

unseal_openbao_node() {
    local node_name=$1
    local unseal_key=$(jq -r ".unseal_keys_b64[]" ${PROTODIR}/openbao/gen/crypto/cluster-keys.json)
    echo "Unsealing $node_name..."
    kubectl exec -n $NAMESPACE $node_name -- bao operator unseal \
        -ca-cert=$CA_CERT_PATH \
        -client-cert=$CLIENT_CERT_PATH \
        -client-key=$CLIENT_KEY_PATH \
        $unseal_key
}

login_to_openbao() {
    local root_token=$(jq -r ".root_token" ${PROTODIR}/openbao/gen/crypto/cluster-keys.json)
    echo "Logging in to openbao-0..."
    kubectl exec -n $NAMESPACE openbao-0 -- bao login \
        -ca-cert=$CA_CERT_PATH \
        -client-cert=$CLIENT_CERT_PATH \
        -client-key=$CLIENT_KEY_PATH \
        $root_token
}

validate_openbao_setup() {
    echo "Validating OpenBao setup..."
    kubectl exec -n $NAMESPACE openbao-0 -- bao operator raft list-peers \
        -ca-cert=$CA_CERT_PATH \
        -client-cert=$CLIENT_CERT_PATH \
        -client-key=$CLIENT_KEY_PATH
    kubectl exec -n $NAMESPACE openbao-0 -- bao status \
        -ca-cert=$CA_CERT_PATH \
        -client-cert=$CLIENT_CERT_PATH \
        -client-key=$CLIENT_KEY_PATH
}

wait_for_openbao
initialize_openbao
unseal_openbao
join_openbao_node "openbao-1"
join_openbao_node "openbao-2"
unseal_openbao_node "openbao-1"
unseal_openbao_node "openbao-2"
login_to_openbao
validate_openbao_setup

echo "=== Manual Step Required ==="
echo "Open a new terminal and run:"
echo "/bin/bash $PROTODIR/scripts/Helpers/openbao-portforward.sh"
echo "Leave that terminal open while continuing."
read -p "Press Enter once port-forward is running and you are ready to proceed... "

echo "This step completed - proceed to Step-04"
