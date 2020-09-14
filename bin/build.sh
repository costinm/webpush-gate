#!/usr/bin/env bash
#set -e

#if ! [ -x "$(command -v ko)" ]; then
#    GO111MODULE=on go get github.com/google/ko/cmd/ko@v0.4.0
#fi

# Local: use local docker, faster
export KO_DOCKER_REPO=${HUB:-localhost:5000}

# Would produce costinm/wps - but skaffold is mangling differently,
# to costinm_wps
# The only solution I know is to make the binary name costinm_wps
#export KO_DOCKER_REPO=localhost:5000/costinm

#env

# IMAGE: localhost:5001/wps:TAG

# -B - use last component of the name

T=$(echo $IMAGE | cut -d: -f 3)
TAG=${T:-latest}
echo TAG $TAG

output=$(ko publish ./cmd/wps --insecure-registry -t $TAG --disable-optimizations -B | tee)


ref=$(echo $output | tail -n1)

# Doesn't work - image is not local
#docker tag $ref $IMAGE
#if $PUSH_IMAGE; then
#    docker push $IMAGE
#fi
