# Using skaffold 

I'm doing a lot of development on a chromebook - without docker, and
with a relatively slow upload speed. Compiling docker images locally 
and uploading to dockerhub is not ideal.

Instead I'm trying to do local test/development locally, but
have the docker images compiled in a K8S cluster, with a K8S-local
registry.

Skaffold is one of the options that automate many of the steps.
Okteto is a similar solution.

## Building in cluster

### Kaniko

Problems:
- if injected with Istio, it'll no properly exit.
- works if using real registry svc address - insecure
- doesn't with localhost - needs istio.

The main issue is exit #6324 - istio can handle localhost.

### Custom

Script will get:
- IMAGE - with tag
- PUSH_IMAGE - true for pushing, else leave it locally
- BUILD_CONTEXT - path to build
- os env
- command can replace env, using go template format
- can run locally or in cluster

- in cluster: pass KUBECONTEXT, NAMESPACE, TIMEOUT

### Docker images

- kaniko - can RUN, etc - slow, file diff

```
kubectl --context gke_costin-istio_us-central1-a_istiod2 exec -i kaniko-nqqxm -c kaniko-init-container -n kube-registry -- tar -xf - -C /kaniko/buildcontext
```

- ko - for go

## Ko

- can replace image in kubeconfig, detect
- image names are strange - but logical

KO_DOCKER_REPO=localhost:5000 ko publish github.com/costinm/wpgate/cmd/wps --insecure-registry -B
KO_DOCKER_REPO=costinm ko publish   --tags=latest github.com/costinm/wpgate/cmd/wps -B

ln -s /home/costin/.cache/google-cloud-tools-java/managed-cloud-sdk/LATEST/google-cloud-sdk/bin/docker-credential-gcloud ~/bin
gcloud auth configure-docker  
KO_DOCKER_REPO=gcr.io/costin-istio ko publish   --tags=latest github.com/costinm/wpgate/cmd/wps -B

- ```shell script

--tag - default latest

-P - not useful, preserve image
--tarball - to save
-L - use local docker, load image
--disable-optimizations
--insecure-registry
-B
```
