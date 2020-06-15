

skaffold:
	SKAFFOLD_DEFAULT_REPO=gcr.io/costin-istio  skaffold dev --cleanup=false --tail  --port-forward=true

skaffold.debug:
	SKAFFOLD_DEFAULT_REPO=gcr.io/costin-istio  skaffold debug --port-forward

docker.push:
	docker build . -t ${IMAGES} && docker push ${IMAGES}

registry:

	export POD=$(shell kubectl get pods --namespace istio-system -l app=kube-registry \
            -o template --template '{{range .items}}{{.metadata.name}} {{.status.phase}}{{"\n"}}{{end}}' \
            | grep Running | head -1 | cut -f1 -d' ')
	echo ${POD}
	kubectl port-forward --namespace istio-system $(POD) 5000:5000 &
	echo $!


kaniko:
	echo Make in cluster $(shell env)
#kubectl --context gke_costin-istio_us-central1-a_istiod2 exec -i kaniko-lc88g\
# 		-c kaniko-init-container -n istio-system -- tar -xf - -C /kaniko/buildcontext

ko:
	go get github.com/google/ko/cmd/ko@v0.4.0
