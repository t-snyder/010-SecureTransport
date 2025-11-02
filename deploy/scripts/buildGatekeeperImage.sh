#!/bin/bash

# Load image to minikube when built
eval $(minikube docker-env)

PROTODIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy

cd $PROTODIR/docker

cp $PROTODIR/../svc-gatekeeper/target/gatekeeper-0.1.jar ./gatekeeper-0.1.jar

docker build -t library/gatekeeper:1.0 -f GatekeeperDockerFile .

rm gatekeeper-0.1.jar

cd ../scripts
