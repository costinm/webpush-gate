
## Istio-secured K8S Local Docker Registry

TL;DR: Run a 'local' registry secured with Istio.

There are 3 ways to use a Docker Registry in a K8S cluster:
- public registry - GCR, dockerhub
- private registry - with a proper TLS certificate
- insecure registry - using "localhost:PORT" address.

The first case is pretty clear. It does require some credentials
that allow write access to the registry to be deployed in the cluster
where the build takes place - which can be tricky to setup and 
not very secure. 

A Private registry is a well documented solution - but it requires a 
proper DNS and certificate - or complicated setup. It still uses some
private credentials, Secrets, etc.

The last solution is normally considered the least secure: registry
is wide open for write to any workload in the cluster. It is also
the easiest to setup. It doesn't work with Skaffold and probably 
other apps - Skaffold is dynamically changing the image in the manifest
to use the same registry. For local registry Skaffold can't use 'localhost'
since there is no local port. 

# Kubelet access

There are 2 viable solutions:

1. (recommended) get a DNS cert for ingress.

# Implementation

As with other apps using Istio, we'll run the Docker registry without any 
security - but in a namespace injected with Istio.

Instead of deploying 'secrets' to apps that need to run the registry
we'll inject a sidecar to any such application. 

For kubelet, we'll use the same mechanism as "kube-registry-proxy", 
i.e. a DaemonSet running with a hostPort. However we'll use a 
 Istio Gateway - which can also server as an Ingress or Egress
 gateway in small clusters. The details are described in a separate
 document. 


# Security

I'm going to use the 'whitebox' mode for the registry, mainly 
because I want to have a good example and test it. 

All communication to Registry will use mTLS, with Istio certificates.

Authentication policies can be used to specify which workloads can 
make write requests. This would also provide an excelent 'dogfood'
and test for the auth.
 
We can also expose the registry via the normal Istio ingress, and
maybe test external access with JWT authentication.  

# Registry details

The registry is running as a ReplicationController with the ```registry:2`` image. It has an
associated persistentVolumeClaim.

# Running in-cluster local registry

Old style: Will start an insecure docker registry plus a port forwarder.

Docker allows localhost to be used as 'insecure' - it relies on the host having 
the port open on localhost.

A daemon set with nodePort is used to forward 'localhost' requests to the actual registry for kubelet.

To access the registry from a remote machine, create a proxy - or use the skaffold file to deploy and
forward:

```shell

 kubectl apply -k github.com/costinm/wpgate/k8s/kube-registry

 POD=$(kubectl get pods --namespace kube-registry -l app=kube-registry \
            -o template --template '{{range .items}}{{.metadata.name}} {{.status.phase}}{{"\n"}}{{end}}' \
            | grep Running | head -1 | cut -f1 -d' ')

 kubectl port-forward --namespace kube-system $POD 5000:5000 &

```

In Istio, HUB will be set to localhost

# TODO

- run a Gateway (envoy) as port forwarder, with full Istio config and mTLS to the registry
- configure the forwarder to allow MTLS/TLS/auth, using istio API.
- configure the proxy to forward to per-namespace registries ? 

The idea would be to have a volume in each namespace with the binary images and .tar.gz 

# Issues

- not secure - could use an Istio sidecar and ingress
- Kaniko won't find localhost
- the kubelet won't find localhost without the proxy - which is also not secure

# Istio integration

1. Run the registry with Istio injection - interception-none to have full control
2. Use a 'replica set' envoy gateway, for node port

# Debugging

## Skaffold

- requires ubuntu or containerless
- 

```shell script
  - command:
    - /dbg/go/bin/dlv
    - exec
    - --headless
    - --continue
    - --accept-multiclient
    - --listen=:56268
    - --api-version=2
    - /bin/sh
    - --
    - -c
    - /usr/local/bin/wps

```

/dbg from debugging-support-files - 
