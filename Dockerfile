FROM golang:latest AS build-base
# dlv doesn't seem to work yet ?
#FROM golang:alpine AS build-base

WORKDIR /ws
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOPROXY=https://proxy.golang.org

#RUN apk add --no-cache git
RUN apt-get update && apt install less net-tools


ENTRYPOINT /bin/sh

################################################################################
FROM build-base AS build

COPY go.mod ./go.mod
COPY go.sum ./go.sum
RUN go mod download

RUN go build -o /ws/dlv github.com/go-delve/delve/cmd/dlv
#RUN   go build -o /ws/ko github.com/google/ko/cmd/ko@v0.4.0


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
COPY --from=build /ws/dlv /usr/local/bin/dlv

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
