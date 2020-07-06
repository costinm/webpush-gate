# Minimalistic Istio Gateway running as hostport

Primary use case: expose a docker registry on the node, on 
port 5000.

It runs in a separate namespace, with no special permissions.

This can also be used to expose other ports on the node,
if the node has public IP addresses. Note that firewalls
may need to be adjusted.

## Random hint

Add
https://raw.githubusercontent.com/istio/api/master/kubernetes/customresourcedefinitions.gen.yaml to
"Settings | Languages & Frameworks | Kubernetes".
