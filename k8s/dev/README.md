# K8S-hosted development environment

## Kubeconfig

For using VSCode K8S plugin, we need to create a config file
on the mounted volume, as /config/.kube/config, since 'in cluster'
is not implemented.

The format of the file is not well documented. Best source
is in client-go/tools/client-cmd/api
