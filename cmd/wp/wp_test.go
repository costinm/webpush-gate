package main

import (
	"testing"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/websocket"
)

// Local testing - using the debug endpoint
func TestWebpush(t *testing.T) {
	mux := msgs.DefaultMux
	a := auth.NewAuth(nil, "test", "example.com")

	err := websocket.WSClient(a, mux, "wss://localhost:5228/ws")
	if err != nil {
		t.Fatal(err)
	}
}
