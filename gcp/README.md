# Code to integrate ugate/wpgate when running in GCP 

## CloudRun

CloudRun provides a very light and cheap environment for running apps. Main limitations are:
- single port (8080) - can be configured a h2, supports long lived connections
- stateless

The app has access to a metadata server with a GCP SA, which can be granted access to:
- pubsub - allow communication between instances and external instances.
- secret store 
- apiserver

## APIserver

```yaml
#GET_CMD="gcloud container clusters describe [CLUSTER] --zone=[ZONE]"

apiVersion: v1
kind: Config
current-context: my-cluster
contexts: [{name: my-cluster, context: {cluster: cluster-1, user: user-1}}]
users: [{name: user-1, user: {auth-provider: {name: gcp}}}]
clusters:
- name: cluster-1
  cluster:
    server: "https://$(eval "$GET_CMD --format='value(endpoint)'")"
    certificate-authority-data: "$(eval "$GET_CMD --format='value(masterAuth.clusterCaCertificate)'")"
```
