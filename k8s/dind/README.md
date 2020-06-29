# Intro

Templates to start a 'dind' with skaffold port forwarding,
for using a docker running in the cluster instead of 
the local machine.

The build context will be uploaded - but compilation
and push to registry happens from the cluster.

# How to use

To use on a remote machine, like chromebook with crostini, after
forwarding the port:


```shell script
export DOCKER_HOST=tcp://localhost:2375

```

The DIND container is alpine based, with busybox.
Exposes a local port 2375 ( PORT env allows different setting).

Inside it uses 'runc'. It must be privileged so it 
can operate on namespaces, but doesn't mount any
host paths and doesn't access the node docker.

# Istio building 

Istio uses something like:

```shell script
docker run --init -it --rm -u 1000:114 \
  --sig-proxy=true \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc/passwd:/etc/passwd:ro\
 -v /etc/group:/etc/group:ro \
  --mount type=bind,source=/tmp,destination=/tmp \
  --net=host \
  --env-file /dev/fd/63 \
  -e IN_BUILD_CONTAINER=1 \
  -e TZ=America/Los_Angeles \
  --mount type=bind,source=/home/costin/work,destination=/work,consistency=delegated --mount type=volume,source=go,destination=/go,consistency=delegated --mount type=volume,source=gocache,destination=/gocache,consistency=delegated --mount type=bind,source=/home/costin/.docker,destination=/config/.docker,readonly,consistency=delegated --mount type=bind,source=/home/costin/.config/gcloud,destination=/config/.config/gcloud,readonly,consistency=delegated --mount type=bind,source=/home/costin/.kube/config,destination=/config/6beb0405,readonly,consistency=delegated 
   -w /work \
  gcr.io/istio-testing/build-tools:master-2020-06-25T05-18-39 \
  make --no-print-directory -e -f Makefile.core.mk
```

It'll not work because of the bind mounts. 

# Local registry
