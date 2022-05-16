module github.com/costinm/wpgate/rtc

go 1.16

// replace github.com/costinm/ugate => ../ugate

require (
	github.com/costinm/ugate v0.0.0-20210221155556-10edd21fadbf
	github.com/pion/datachannel v1.4.21
	github.com/pion/logging v0.2.2
	github.com/pion/sctp v1.7.11
	github.com/pion/turn/v2 v2.0.5
	github.com/pion/webrtc/v3 v3.0.15
	golang.org/x/sys v0.0.0-20210220050731-9a76102bfb43 // indirect
)
