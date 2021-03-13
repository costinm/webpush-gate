package websocket

import (
	"testing"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/transport/xds/webpush"
)

// Local testing - using the debug endpoint
func TestWebpush(t *testing.T) {
	mux := webpush.DefaultMux
	a := auth.NewAuth(nil, "test", "example.com")

	err := WSClient(a, mux, "wss://localhost:5228/ws")
	if err != nil {
		t.Fatal(err)
	}
}
