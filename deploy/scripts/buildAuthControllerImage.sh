#!/bin/bash

# Load image to minikube when built
eval $(minikube docker-env)

PROTODIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy

cd $PROTODIR/docker

cp $PROTODIR/../svc-authController/target/authcontroller-0.1.jar ./authcontroller-0.1.jar

docker build -t library/authcontroller:1.0 -f AuthControllerDockerFile .

rm authcontroller-0.1.jar

cd ../scripts
