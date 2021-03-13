module github.com/costinm/wpgate/gcp

go 1.16

//replace github.com/costinm/ugate => ../../ugate

require (
	cloud.google.com/go v0.78.0
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect
	google.golang.org/api v0.40.0
	google.golang.org/genproto v0.0.0-20210226172003-ab064af71705
	k8s.io/apimachinery v0.20.4
	k8s.io/client-go v0.20.4
)
