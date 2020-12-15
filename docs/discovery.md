# Discovery options

## IPFS

DHT

Pros:
- large infrastructure
- signed blobs

Cons:
- very noisy for the public infra - ok for private but loses the benefit
of the large public infra
- lots of connections

## Central server(s)

- K8S Apiserver, backed by replicated etcd or EndpointSlice sync
- Istio XDS, backed by whatever
- Syncthing

## Hierarchical

- DNS - possibly on a 'virtual'/private namespace, possibly signed

