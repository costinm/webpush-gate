#!/usr/bin/env bash

export KO_DOCKER_REPO=localhost:5000

TAG=$(echo $IMAGE | cut -d: -f 3)
export GOMAXPROCS=1
export KO_CONFIG_PATH=$BUILD_CONTEXT/../wpgate


echo TAG $TAG KO_CONFIG_PATH $KO_CONFIG_PATH BUILD_CONTEXT $BUILD_CONTEXT
echo KUBECONTEXT $KUBECONTEXT Ns $NAMESPACE
#cd ${HOME}/src/istio
cd ${HOME}/work
# May be sensitive to paths

output=$(ko publish ./pilot/cmd/pilot-discovery --insecure-registry -t $TAG --disable-optimizations -B | tee)

ref=$(echo $output | tail -n1)

# Doesn't work - image is not local
#docker tag $ref $IMAGE
#if $PUSH_IMAGE; then
#    docker push $IMAGE
#fi
