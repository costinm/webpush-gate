function kx() {
	local ns=$1
	shift
	local app=$1
	shift 
	kubectl -n $ns exec  $(kubectl --namespace=${ns} get pod -l ${app}  -o=jsonpath='{.items[0].metadata.name}') -c istio-proxy $*
}

function kxa() {
	local ns=$1
	shift
	local app=$1
	shift
	kubectl -n $ns exec  $(kubectl --namespace=${ns} get pod -l ${app}  -o=jsonpath='{.items[0].metadata.name}') -c app $*
}

function kxl() {
	local ns=$1
	shift
	local app=$1
	shift
	kubectl -n $ns logs  $(kubectl --namespace=${ns} get pod -l ${app}  -o=jsonpath='{.items[0].metadata.name}') -c app $*
}
