# Istio-secured K8S Local Docker Registry

TL;DR: Run a 'local' docker registry secured with Istio, using a Gateway daemonset with strict mTLS.

## Background: Current solutions

There are 3 ways to use a Docker Registry in a K8S cluster:
- public registry - GCR, dockerhub
- private registry - with a proper TLS certificate
- insecure registry - using "localhost:PORT" address.

Docker by default requires DNS (ACME) certificate for any registry except localhost, and clients require special permission to write to the registry,
and for non-public registries for read. Docker allows localhost to be used as 'insecure' - it relies on the host having the 5000 port open on localhost.

The first case is pretty clear and common. It does require some credentials
that allow write access to the registry to be deployed in the cluster
where the build takes place - which can be tricky to setup and 
not very secure: the registry credentials will be stored in a namespace
accessible to the build. Even on GCP, the builder needs IAM permissions to GCR. 

A Private registry is a well documented solution - but it requires a 
proper DNS and certificate - or complicated setup. It still uses some
private credentials - stored as Secrets. 

The last solution is normally considered the least secure: registry
is wide open for write to any workload in the cluster. It is also
the easiest to setup: run the registry in cluster, a proxy on each node, and 
use "localhost:5000" in the manifests. 

## Istio-based solution

The charts run the registry in cluster, with an Istio sidecar. That means
access to registry requires Istio MTLS and can be controlled using Istio policy.
User may optionally expose it in the gateway and use certificates auto-generated
by Istio.

On each node, using a daemonset we run an Istio Gateway. The gateway runs with
'hostPort' set to 5000 - so pods using "localhost:5000" will connect to Istio 
gateway on localhost (generally secure). Istio Gateway will then use mTLS to
connect to the real registry, with mutual authentication. 

The Istio Policy for the registry can use the identity of the gateway to allow
'read only' access, and may use the workload identity of the builder to grant
write access to specific repositories.

For example, a "example-builder" namespace running an in-cluster build can be 
granted write access to the registry for 'example' repo. 

# Implementation

As with other apps using Istio, we'll run the Docker registry without any 
security, but on localhost:5000: the pod should not bind to 0.0.0.0.

Instead of deploying 'secrets' to apps that need to run the registry
we'll use Istio Gateway or Sidecar, ensuring access to the registry is 
secured and policy-protected. 

For kubelet, we'll use the same mechanism as "kube-registry-proxy", 
i.e. a DaemonSet running with a hostPort. 

# Using the DaemonSet gateway for other purposes

We are deploying a standard Istio Gateway for access to the registry. The 
gateway is using hostPort on 5000 for registry access. 

Users may open additional hostPorts - for example 443, 80, etc - and use this
daemon set as a normal ingress or egress gateway. On GKE user will need to 
configure the firewall rules manually to allow external access: for regular
gateway this is handled when creating the LB Service. Users also need to 
manage the DNS entries and node IPs. 

While this is more complicated - it avoids the use of an external load balancer,
and for development/local/test clusters with few stable nodes it can be lighter.

# Security

All communication to Registry will use mTLS, with Istio certificates.

Authentication policies can be used to specify which workloads can 
make write requests. This would also provide an excelent 'dogfood'
and test for the auth.
 
# Skaffold and 'local' development

A Istio docker registry doesn't work well with Skaffold and probably other apps - Skaffold is dynamically changing the image in the manifest to use the same registry. 

One solution is to do a port-forward from the registry to the dev machine: if the developer has RBAC permissions on the registry namespace or cluster it can already control it.


```shell

 POD=$(kubectl get pods --namespace kube-registry -l app=kube-registry \
            -o template --template '{{range .items}}{{.metadata.name}} {{.status.phase}}{{"\n"}}{{end}}' \
            | grep Running | head -1 | cut -f1 -d' ')

 kubectl port-forward --namespace kube-registry $POD 5000:5000 &

```

A second option is for developer to run a local Istio gateway on the development
machine, and forward localhost:5000 using the ingress gateway. In this mode a 
developer with RBAC permission restricted to a namespace will also be subject
to Istio policies. 


# Issues

- security not fully implemented according to the design - WIP on policy, etc
- Kaniko won't find localhost, injection needs to be customized

- gateway binds on 0.0.0.0 - need additional filter to protect against remote clients
using the port with a Host header. The gateway on 5000 should be read only.

# TODO

- configure the proxy to forward to per-namespace registries ? Not sure if kubelet provides enough information.

