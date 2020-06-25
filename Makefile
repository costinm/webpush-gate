build:
	go build ./cmd/wps

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


setup:
	kubectl get secret istio-ca-secret -n istio-system -o "jsonpath={.data['ca-cert\.pem']}" | base64 -d > tls.crt
	kubectl get secret istio-ca-secret -n istio-system -o "jsonpath={.data['ca-key\.pem']}" | base64 -d > tls.key
	kubectl -n istio-system create secret generic istio-certmanager-ca --from-file tls.crt=tls.crt --from-file ca.crt=tls.crt --from-file tls.key=tls.key || true
	rm tls.key tls.crt

cm-install:
	kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.15.0/cert-manager.yaml
	kubectl -n istio-system apply -f istio-issuer.yaml

HELM3_VERSION=3.1.2
HELM3_RELEASE_ROOT="https://get.helm.sh"
HELM3_RELEASE_FILE="helm-v${HELM3_VERSION}-linux-amd64.tar.gz"

install-helm3:
	curl -L ${HELM3_RELEASE_ROOT}/${HELM3_RELEASE_FILE} |tar xvz && \
    	mv linux-amd64/helm ${HOME}/go/bin/helm3 && \
    	chmod +x ${HOME}/go/bin/helm3
