#!/usr/bin/env bash
#set -e

#if ! [ -x "$(command -v ko)" ]; then
#    GO111MODULE=on go get github.com/google/ko/cmd/ko@v0.4.0
#fi

# Local: use local docker, faster
export KO_DOCKER_REPO=localhost:5000

env

TAG=$(echo $IMAGE | cut -d: -f 3)
echo TAG $TAG
output=$(ko publish ./cmd/wps --insecure-registry -t $TAG --disable-optimizations -B | tee)
ref=$(echo $output | tail -n1)

#docker tag $ref $IMAGE
#if $PUSH_IMAGE; then
#    docker push $IMAGE
#fi
