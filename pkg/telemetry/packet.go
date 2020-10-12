package telemetry

import (
	"expvar"
	"log"
	"net"
	"strings"
	"time"

	"github.com/zserge/metric"
)


var (
	QuicDebugClient = false
	QuicDebugServer = false
	//quicClientRead    = expvar.NewInt("quicClientRead")
	//quicClientReadPk  = expvar.NewInt("quicClientReadPk")
	//quicClientReadErr = expvar.NewMap("quicClientReadErr")
	//
	//quicClientWrite   = expvar.NewInt("quicClientWrite")
	//quicClientWritePk = expvar.NewInt("quicClientWritePk")
	//
	//quicSRead    = expvar.NewInt("quicSrvRead")
	//quicSReadPk  = expvar.NewInt("quicSrvReadPk")
	//quicSWrite   = expvar.NewInt("quicSrvWrite")
	//quicSWritePk = expvar.NewInt("quicSrvWritePk")
	//
	//quicDialCnt       = expvar.NewInt("quicClientDial")
	//quicDialErrListen = expvar.NewInt("quicClientDialListen")
	//quicDialErrDial   = expvar.NewInt("quicClientDialErr")

	quicDialErrs = expvar.NewMap("quicDialErr")
)

var (
	quicClientRead       = metric.NewGauge("15m10s", "1h1m")
	quicClientReadPk     = metric.NewGauge("15m10s")
	quicClientReadErrCnt = metric.NewCounter("15m10s")
	quicClientReadErr    = expvar.NewMap("quicClientReadErr")

	quicClientWrite   = metric.NewCounter("15m10s")
	quicClientWritePk = metric.NewCounter("15m10s")

	quicSRead    = metric.NewCounter("15m10s")
	quicSReadPk  = metric.NewCounter("15m10s")
	quicSWrite   = metric.NewCounter("15m10s")
	quicSWritePk = metric.NewCounter("15m10s")

	quicDialCnt       = metric.NewGauge("15m10s")
	quicDialErrListen = metric.NewCounter("15m10s")
	quicDialErrDial   = metric.NewCounter("15m10s")
)

func init() {
	expvar.Publish("quicClientRead", quicClientRead)
	expvar.Publish("quicClientReadPk", quicClientReadPk)
	expvar.Publish("quicClientReadErrCnt", quicClientReadErrCnt)

	expvar.Publish("quicClientWrite", quicClientWrite)
	expvar.Publish("quicClientWritePk", quicClientWritePk)

	expvar.Publish("quicSrvRead", quicSRead)
	expvar.Publish("quicSrvReadPk", quicSReadPk)
	expvar.Publish("quicSrvWrite", quicSWrite)
	expvar.Publish("quicSrvWritePk", quicSWritePk)

	expvar.Publish("quicClientDial", quicDialCnt)
	expvar.Publish("quicClientDialErr", quicDialErrDial)
}

// Wrap a packet conn, display messages and adjust addresses.
type ClientPacketConnWrapper struct {
	PacketConn   net.PacketConn
	PacketConnAP net.PacketConn

	// Address - set in client mode
	addr string

	start time.Time
	sent  int
	rcv   int

	useApHack bool
}

func (c *ClientPacketConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	con := c.PacketConn
	if c.PacketConnAP != nil {
		con = c.PacketConnAP
	}
	l, a, e := con.ReadFrom(b)
	if QuicDebugClient || e != nil {
		if e != nil && !strings.Contains(e.Error(), "use of closed network connection") {
			log.Println("QC Read: ", l, a, e, c.addr)
		}
	}
	quicClientReadPk.Add(1)
	quicClientRead.Add(float64(l))
	c.rcv += l
	if e != nil {
		quicClientReadErr.Add(e.Error(), 1)
		quicClientReadErrCnt.Add(1)
	}
	return l, a, e
}

func (c *ClientPacketConnWrapper) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	udp, ok := addr.(*net.UDPAddr)
	if ok {
		zone := udp.Zone
		if c.useApHack && strings.Contains(zone, "p2p") &&
				udp.IP[0] == 0xfe {
			udp.IP[0] = 0xff
			udp.IP[1] = 2
			udp.Port++ // TODO: maintain a port map (based on registry data) if ports are not in order
			// Normally for client connection Registry is already maintaining the right IP/port
			if true || QuicDebugClient {
				log.Println("OVERRIDE", udp, udp.IP)
			}
		} else {
			ok = false
		}
		addr = udp
	}

	n, err = c.PacketConn.WriteTo(b, addr)
	if QuicDebugClient || err != nil {
		log.Println("QC Write: ", n, err, c.addr, udp)
	}
	quicClientWritePk.Add(1)
	quicClientWrite.Add(float64(n))
	c.sent += n
	return
}
func (c *ClientPacketConnWrapper) Close() error {
	e := c.PacketConn.Close()
	if c.PacketConnAP != nil {
		c.PacketConnAP.Close()
	}
	// Can be called by establishSecureConnection for Crypto handshake did not complete...
	log.Println("QC: CloseUDP ", c.addr, time.Since(c.start), c.sent, c.rcv)
	return e
}

func (c *ClientPacketConnWrapper) LocalAddr() net.Addr {
	a := c.PacketConn.LocalAddr()
	if QuicDebugClient {
		log.Println("QC LocalAddr", a, c.addr)
	}
	return a
}

func (c *ClientPacketConnWrapper) SetDeadline(t time.Time) error {
	e := c.PacketConn.SetDeadline(t)
	log.Println("QC SetDeadline", t, c.addr)
	return e
}

func (c *ClientPacketConnWrapper) SetReadDeadline(t time.Time) error {
	e := c.PacketConn.SetReadDeadline(t)
	log.Println("QC SetReadDeadline", t, c.addr)
	return e
}

func (c *ClientPacketConnWrapper) SetWriteDeadline(t time.Time) error {
	e := c.PacketConn.SetReadDeadline(t)
	log.Println("QC SetReadDeadline", t, c.addr)
	return e
}

type PacketConnWrapper struct {
	PacketConn net.PacketConn
	useApHack  bool
}

func (c *PacketConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	l, a, e := c.PacketConn.ReadFrom(b)
	if QuicDebugServer {
		log.Println("SW Read: ", l, a, e)
	}
	// TODO: routing based on connection ID 1!!
	quicSReadPk.Add(1)
	quicSRead.Add(float64(l))

	return l, a, e
}

func (c *PacketConnWrapper) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	udp, ok := addr.(*net.UDPAddr)
	if ok {
		zone := udp.Zone
		if c.useApHack && strings.Contains(zone, "p2p") &&
				udp.IP[0] == 0xfe {
			udp.IP[0] = 0xff
			udp.IP[1] = 2
			udp.Port++ // TODO: maintain a port map (based on registry data) if ports are not in order
			// Normally for client connection Registry is already maintaining the right IP/port
			if QuicDebugServer {
				log.Println("SRV OVERRIDE", udp, udp.IP)
			}
		} else {
			ok = false
		}
		addr = udp
	}

	n, err = c.PacketConn.WriteTo(b, addr)
	if QuicDebugServer {
		log.Println("QS Write: ", n, err, ok, udp)
	}
	quicSWritePk.Add(1)
	quicSWrite.Add(float64(n))
	return
}

func (c *PacketConnWrapper) Close() error {
	e := c.PacketConn.Close()
	log.Println("QS CloseUDP ", e)
	return e
}

// Client only seems to call it for the debug, in server.go/Listen
func (c *PacketConnWrapper) LocalAddr() net.Addr {
	a := c.PacketConn.LocalAddr()
	//log.Println("QS LocalAddr", a)
	return a
}
func (c *PacketConnWrapper) SetDeadline(t time.Time) error {
	e := c.PacketConn.SetDeadline(t)
	log.Println("QS SetDeadline", t)
	return e
}

func (c *PacketConnWrapper) SetReadDeadline(t time.Time) error {
	e := c.PacketConn.SetReadDeadline(t)
	log.Println("QS SetReadDeadline", t)
	return e
}
func (c *PacketConnWrapper) SetWriteDeadline(t time.Time) error {
	e := c.PacketConn.SetReadDeadline(t)
	log.Println("QS SetWriteDeadline", t)
	return e

}
