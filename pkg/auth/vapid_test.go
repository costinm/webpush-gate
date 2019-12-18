package auth

import (
	"testing"

	"github.com/costinm/webpush-gate/webpush"
)

// Chrome/mozilla are testing interop with real servers

func BenchmarkToken(b *testing.B) {
	vapid := NewVapid(vapidPub, vapidPriv)

	for i := 0; i < b.N; i++ {
		vapid.Token("https://foo.com/bar")
	}
}
