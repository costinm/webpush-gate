# K8S-hosted development environment

## Kubeconfig

For using VSCode K8S plugin, we need to create a config file
on the mounted volume, as /config/.kube/config, since 'in cluster'
is not implemented.

The format of the file is not well documented. Best source
is in client-go/tools/client-cmd/api

# Docker Image

First option: fork from docker-code-server.
The 'base' image has a lot of stuff, can't just replace it
with Istio image. Dead end.


Second option - base it in istio-testing/build-tools and add code server.
Seems to work.

```shell script

```

