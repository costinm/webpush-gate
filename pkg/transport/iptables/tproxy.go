package iptables

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/costinm/wpgate/pkg/mesh"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// WIP: requires root, UDP proxy using orig dest.
// Only useful for inbound - where we already know the dest.

func StartTproxy(p *mesh.Gateway, addr string) error {
	var f *os.File
	var err error
	if p.UDPListener == nil {
		// Requires root, not starting UDP proxy
		//return nil
		f, err = StartUDPTProxyListener(15006)
		if err != nil {
			log.Println("Error starting TPROXY", err)
			return err
		}
	} else {
		f = p.UDPListener
	}
	c, err := net.FileConn(f)
	if err != nil {
		return err
	}

	lu, ok := c.(*net.UDPConn)
	if !ok {
		return errors.New("failed to cast")
	}

	p.UDPWriter = &transparentUdp{con: lu}

	//lu, err := net.ListenUDP("udp", &net.UDPAddr{
	//	Port: 15000,
	//})
	//if err != nil {
	//	return err
	//}
	//int flags = 1;
	//ret = setsockopt(udp_socket, IPPROTO_IP, IP_RECVORIGDSTADDR, &flags, sizeof(flags));

	go func() {
		data := make([]byte, 1600)
		oob := ipv4.NewControlMessage(ipv4.FlagDst)
		//oob := make([]byte, 256)
		for {

			n, noob, _, addr, err := lu.ReadMsgUDP(data[0:], oob)
			if err != nil {
				continue
			}

			cm4, err := syscall.ParseSocketControlMessage(oob[0:noob])
			origPort := uint16(0)
			var origIP net.IP
			for _, cm := range cm4 {
				if cm.Header.Type == unix.IP_RECVORIGDSTADDR {
					// \attention: IPv4 only!!!
					// address type, 1 - IPv4, 4 - IPv6, 3 - hostname, only IPv4 is supported now
					rawaddr := make([]byte, 4)
					// raw IP address, 4 bytes for IPv4 or 16 bytes for IPv6, only IPv4 is supported now
					copy(rawaddr, cm.Data[4:8])
					origIP = net.IP(rawaddr)

					// Bigendian is the network bit order, seems to be used here.
					origPort = binary.BigEndian.Uint16(cm.Data[2:])

				}
			}
			//if cm4.Parse(oob) == nil {
			//dst = cm4.Dst
			//}
			//log.Printf("NOOB %d %d %V %x", noob, flags, cm4, oob[0:noob])
			//if ((cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == IP_RECVORIGDSTADDR))
			//{
			//	memcpy (&dstaddr, CMSG_DATA(cmsg), sizeof (dstaddr));
			//	dstaddr.sin_family = AF_INET;
			//}

			go p.UDPGate.HandleUdp(origIP, origPort, addr.IP, uint16(addr.Port), data[0:n])
		}
	}()

	return nil
}

// Initialize a port as a TPROXY socket. This can be sent over UDS from the root, and used for
// UDP capture.
func StartUDPTProxyListener(port int) (*os.File, error) {
	// TPROXY mode for UDP - alternative is to use REDIRECT and parse
	// /proc/net/nf_conntrack
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}

	err = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err != nil {
		return nil, err
	}

	// NET_CAP
	err = unix.SetsockoptInt(s, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	if err != nil {
		fmt.Println("TRANSPARENT err ", err)
		//return err
	}

	err = unix.SetsockoptInt(s, unix.SOL_IP, unix.IP_FREEBIND, 1)
	if err != nil {
		fmt.Println("FREEBIND err ", err)
		//return err
	}

	err = unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR, 1)
	if err != nil {
		return nil, err
	}
	log.Println("Openned TPROXY capture port in TRANSPARENT mode ", port)
	err = unix.Bind(s, &unix.SockaddrInet4{
		Port: port,
	})
	if err != nil {
		log.Println("Error binding ", err)
		return nil, err
	}

	f := os.NewFile(uintptr(s), "TProxy")
	return f, nil
}

//
type transparentUdp struct {
	con *net.UDPConn
}

// UDP write with source address control.
func (tudp *transparentUdp) WriteTo(data []byte, dstAddr *net.UDPAddr, srcAddr *net.UDPAddr) (int, error) {

	// Attempt to write as UDP
	cm4 := new(ipv4.ControlMessage)
	cm4.Src = srcAddr.IP
	oob := cm4.Marshal()
	n, _, err := tudp.con.WriteMsgUDP(data, oob, dstAddr)
	if err != nil {
		n, err = tudp.con.WriteToUDP(data, dstAddr)
		if err != nil {
			log.Print("Failed to send DNS ", dstAddr, srcAddr)
		}
	}

	return n, err // tudp.con.WriteTo(data, dstAddr)
}
