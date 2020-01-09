

skaffold:
	SKAFFOLD_DEFAULT_REPO=gcr.io/costin-istio  skaffold dev --cleanup=false --tail  --port-forward=true

skaffold.debug:
	SKAFFOLD_DEFAULT_REPO=gcr.io/costin-istio  skaffold debug --port-forward

docker.push:
	docker build . -t ${IMAGES} && docker push ${IMAGES}
