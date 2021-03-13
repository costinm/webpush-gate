package mesh

import (
	"fmt"
	"net"
	"time"
)

const (
	TopicConnectUP = "connectUP"
)

// Track one interface.
type ActiveInterface struct {
	// Interface name. Name containing 'p2p' results in specific behavior.
	Name string

	// IP6 link local address. May be nil if IPPub is set.
	// One or the other must be set.
	IP6LL net.IP

	// IP4 address - may be a routable address, nil or private address.
	// If public address - may be included in the register, but typically not
	// useful.
	IP4 net.IP

	// Public addresses. IP6 address may be used for direct connections (in some
	// cases)
	IPPub []net.IP

	// Port for the UDP unicast link-local listener.
	Port int
	// Port for the UDP unicast link-local listener.
	Port4 int

	// True if this interface is an Android AP
	AndroidAP bool

	// True if this interface is connected to an Android DM node.
	AndroidAPClient bool
}

type ScanResults struct {
	// Visible devices at this moment
	Scan []*MeshDevice `json:"scan,omitempty"`

	Stats string `json:"stat,omitempty"`

	// Visible wifi networks (all kinds)
	Visible int `json:"visible,omitempty"`

	// My SSID and PSK
	SSID          string `json:"s,omitempty"`
	PSK           string `json:"p,omitempty"`
	ConnectedWifi string `json:"w,omitempty"`
	Freq          int    `json:"f,omitempty"`
	Level         int    `json:"l,omitempty"`
}

// WifiRegistrationInfo contains information about the wifi node sent to the
// other nodes, to sync up visibility info.
//
type WifiRegistrationInfo struct {
	// Visible P2P devices in the mesh. This includes active APs as well as devices announcing via
	// BLE or NAN (or other means).
	Devices map[string]*MeshDevice `json:"devices,omitempty"`

	SSID string `json:"ssid,omitempty"`
	PSK  string `json:"psk,omitempty"`

	// Network we are connected to.
	// TODO: In case of chained P2P networks, should be either the path, or a separate field should include the path
	// and the net should be the 'top level' network of the root.
	Net string `json:"net,omitempty"`

	// Number of visible wifi networks (all kinds)
	VisibleWifi int `json:"scanCnt,omitempty"`
}

// Info about a device from the P2P info.
type MeshDevice struct {
	SSID string `json:"s,omitempty"`
	PSK  string `json:"p,omitempty"`

	// MAC is used with explicit P2P connect ( i.e. no hacks )
	// User input required on the receiving end ( PBC )
	MAC string `json:"d,omitempty"`

	Name string `json:"N,omitempty"`

	// Set only if the device is currently visible in scan
	Level int `json:"l,omitempty"`
	Freq  int `json:"f,omitempty"`

	// Extracted from DIRECT DNSSD
	UserAgent string `json:"ua,omitempty"`
	Net       string `json:"n,omitempty"`

	Cap   string `json:"c,omitempty"`
	BSSID string `json:"b,omitempty"`

	LastSeen time.Time `json:"lastSeen,omitempty"`

	Self int `json:"self,omitempty"`
	// Only on supplicant,not on android
	ServiceUpdateInd int `json:"sui,omitempty"`
}

func (md *MeshDevice) String() string { return fmt.Sprintf("%s/%d", md.SSID, md.Level) }
