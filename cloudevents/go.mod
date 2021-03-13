module github.com/costinm/wpgate/cloudevents

go 1.16

replace github.com/costinm/ugate => ../../ugate

require (
	cloud.google.com/go v0.78.0 // indirect
	cloud.google.com/go/pubsub v1.3.1
	github.com/cloudevents/sdk-go v1.2.0
	github.com/cloudevents/sdk-go/v2 v2.3.1
	github.com/costinm/ugate v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect
	google.golang.org/genproto v0.0.0-20210226172003-ab064af71705 // indirect
)
