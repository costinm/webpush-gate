IMAGE ?= costinm/wps:latest
GOPATH ?= ${HOME}/go

build:
	go build ./cmd/wps

# Must be run first, to initialize the registry and req.
prepare: skaffold/registry

deps: deps/esc deps/helm3 deps/ko

gen: pkg/ui/html_static.go

skaffold/registry:
	cd k8s/kube-registry && \
		SKAFFOLD_DEFAULT_REPO=costinm skaffold dev --cleanup=false --port-forward=true

skaffold:
	SKAFFOLD_DEFAULT_REPO=localhost:5000 skaffold dev --cleanup=false --tail  --port-forward=true

skaffold/debug:
	SKAFFOLD_DEFAULT_REPO=localhost:5000 skaffold debug --port-forward

docker/push:
	docker build . -t ${IMAGE} && docker push ${IMAGE}

registry:
	POD=$(shell kubectl get pods --namespace kube-registry -l app=kube-registry \
            -o template --template '{{range .items}}{{.metadata.name}} {{.status.phase}}{{"\n"}}{{end}}' \
            | grep Running | head -1 | cut -f1 -d' ')
	export POD
	echo ${POD}
	(kubectl port-forward --namespace kube-registry ${POD} 5000:5000 ) && echo $!

deps/ko:
	go get github.com/google/ko/cmd/ko@v0.4.0


cm/setup:
	kubectl get secret istio-ca-secret -n istio-system -o "jsonpath={.data['ca-cert\.pem']}" | base64 -d > tls.crt
	kubectl get secret istio-ca-secret -n istio-system -o "jsonpath={.data['ca-key\.pem']}" | base64 -d > tls.key
	kubectl -n istio-system create secret generic istio-certmanager-ca --from-file tls.crt=tls.crt --from-file ca.crt=tls.crt --from-file tls.key=tls.key || true
	rm tls.key tls.crt

cm/install:
	kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.15.0/cert-manager.yaml
	kubectl -n istio-system apply -f istio-issuer.yaml

HELM3_VERSION=3.1.2
HELM3_RELEASE_ROOT="https://get.helm.sh"
HELM3_RELEASE_FILE="helm-v${HELM3_VERSION}-linux-amd64.tar.gz"

deps/helm3:
	curl -L ${HELM3_RELEASE_ROOT}/${HELM3_RELEASE_FILE} |tar xvz && \
    	mv linux-amd64/helm ${HOME}/go/bin/helm3 && \
    	chmod +x ${HOME}/go/bin/helm3

deps/esc:
	go get -u github.com/mjibson/esc

# Generate static files
pkg/ui/html_static.go: ${GOPATH}/bin/esc  pkg/ui/www/status.html \
        pkg/ui/www/active.html \
        pkg/ui/www/peers.html \
        pkg/ui/www/wifi.html \
		pkg/ui/www/events.html \
        pkg/ui/www/base.html \
        pkg/ui/www/js/index.js \
		pkg/ui/www/info.html
	@echo "REGENERAGE"
	${GOPATH}/bin/esc -include '.*\.html|.*\.js|.*\.css' -prefix pkg/ui/www -o pkg/ui/html_static.go -pkg ui pkg/ui/www/

OUT ?= ${HOME}/go
GO ?= go

cross: arm arm64 mips

arm64:
	GOARCH=arm64 GOOS=linux GOARM=7 ${GO} build -o ${OUT}/bin/arm64/wps -ldflags="-s -w" ./cmd/wps

# Arm, mips: Noise has errors with curve25519
arm:
	GOARCH=arm GOOS=linux GOARM=7 ${GO} build -o ${OUT}/bin/arm/wps -ldflags="-s -w" ./cmd/wps

mips:
	GOARCH=mips GOOS=linux GOMIPS=softfloat  ${GO} build -ldflags="-s -w" -o ${OUT}/bin/mips/wps ./cmd/wps

androidAll:
	time OUT=${TOP} GOOS=linux GOARCH=arm GOARM=7 ${GO} build -ldflags="-s -w" -o ${DM_ARM} ${PKG}/cmd/libDM
	time OUT=${TOP} GOOS=linux GOARCH=arm64 ${GO} build -ldflags="-s -w" -o ${DM_ARM64} ${PKG}/cmd/libDM
	time OUT=${TOP} GOOS=linux GOARCH=amd64 ${GO} build -ldflags="-s -w" -o ${DM_X8664} ${PKG}/cmd/libDM
	time OUT=${TOP} GOOS=linux GOARCH=386 ${GO} build -ldflags="-s -w" -o ${DM_X86} ${PKG}/cmd/libDM

android:
	time OUT=${TOP} GOOS=linux GOARCH=arm GOARM=7 ${GO} build -ldflags="-s -w" -o ${DM_ARM} ${PKG}/cmd/libDM
	time OUT=${TOP} GOOS=linux GOARCH=arm64 ${GO} build -ldflags="-s -w" -o ${DM_ARM64} ${PKG}/cmd/libDM
