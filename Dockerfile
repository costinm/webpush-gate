FROM golang:latest AS build-base
#FROM golang:alpine AS build-base

WORKDIR /ws
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOPROXY=https://proxy.golang.org

#RUN apk add --no-cache git
#
#RUN go get github.com/go-delve/delve/cmd/dlv && \
# go get github.com/google/ko/cmd/ko@v0.4.0
## With caching should avoid repeated downloads as long as the sum/mod don't change
#COPY go.mod go.sum  ./
#RUN go mod download
########
#FROM golang:latest AS build_base
#
RUN apt-get update && apt install less net-tools
RUN go get github.com/go-delve/delve/cmd/dlv && \
   go get github.com/google/ko/cmd/ko@v0.4.0
ENTRYPOINT /bin/sh

################################################################################
##### Run the build on alpine - istiod doesn't need more.
## Main docker images for istiod will be distroless and alpine.
##FROM golang:1.13-alpine AS build-base1
##
##WORKDIR /ws
##ENV GO111MODULE=on
##ENV CGO_ENABLED=0
##ENV GOOS=linux
##ENV GOPROXY=https://proxy.golang.org
##
##RUN apk add --no-cache git
##
##RUN go get github.com/go-delve/delve/cmd/dlv && \
## go get github.com/google/ko/cmd/ko@v0.4.0
### With caching should avoid repeated downloads as long as the sum/mod don't change
##COPY go.mod go.sum  ./
##RUN go mod download
#########
##FROM gcr.io/istio-testing/build-tools:master-2020-05-20T22-13-03 AS istio_build
##
##RUN apt-get update && apt install less net-tools
#
################################################################################
FROM build-base AS build

COPY cmd ./cmd
COPY pkg ./pkg

# Runs in /go directory
RUN go build -a -gcflags='all=-N -l' -ldflags '-extldflags "-static"' -o wps ./cmd/wps

#
################################################################################
#### Container running the combined control plane, with an alpine base ( smaller than distroless but with shell )
#### TODO: add a distroless variant.
#### This image should work as a drop-in replacement for Pilot, Galley(MCP portion), WebhookInjector
#### Citadel, Gallye/Validation remain as separate deployments.
##FROM envoyproxy/envoy-alpine:v1.14.1 AS wps
##FROM debian:10-slim AS wps
#
## Same base as Istio debug
FROM ubuntu:bionic AS wps
# Or distroless
#FROM docker.io/istio/base:default AS wps

COPY --from=build /ws/wps /usr/local/bin/wps

WORKDIR /
#RUN mkdir -p /etc/certs && \
#    mkdir -p /etc/istio/proxy && \
#    mkdir -p /etc/istio/config && \
#    mkdir -p /var/lib/istio/envoy && \
#    mkdir -p /var/lib/istio/config && \
#    mkdir -p /var/lib/istio/proxy && \
#    chown -R 1337 /etc/certs /etc/istio /var/lib/istio

# Defaults
#COPY ./var/lib/istio /var/lib/istio/
USER 5228:5228
ENTRYPOINT /usr/local/bin/wps
