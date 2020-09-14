package admin

import (
	"context"
	"os"

	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
)

// Message handlers and HTTPS URLs reserved to the 'admin' role.
// The admin must be configured in the authorized_hosts
//
// One option is to use the public key of a device, run UI on localhost:5227,
// and use the forwarding mechanism. 'wp' and curl with client certs also work.

func NewAdmin(gw *mesh.Gateway, h2 *h2.H2, mux *msgs.Mux) {

	mux.AddHandler("/quitquitquit", msgs.HandlerCallbackFunc(func(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
		os.Exit(0)
	}))

}
