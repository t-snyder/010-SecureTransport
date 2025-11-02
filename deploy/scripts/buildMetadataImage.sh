#!/bin/bash

# Load image to minikube when built
eval $(minikube docker-env)

PROTODIR=/media/tim/ExtraDrive1/Projects/010-SecureTransport/deploy

cd $PROTODIR/docker

cp $PROTODIR/../svc-metadata/target/metadatasvc-0.1.jar ./metadatasvc-0.1.jar

docker build -t library/metadatasvc:1.0 -f MetadataDockerFile .

rm metadatasvc-0.1.jar

cd ../scripts
