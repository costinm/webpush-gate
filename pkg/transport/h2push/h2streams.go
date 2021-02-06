package h2push

import (
	"bytes"
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type H2SCfg struct {
	OnConnection func(s *Session)
	Handler http.Handler
}

// A Listener for incoming H2 connections, acting as server.
// Implements a similar interface with Quic
type Listener interface {
	// Close the server. All active sessions will be closed.
	Close() error
	// Addr returns the local network addr that the server is listening on.
	Addr() net.Addr
	// Accept returns new sessions. It should be called in a loop.
	Accept(context.Context) (Session, error)
}

type H2SServer struct {
	ownListener bool
	ll          net.Listener
	addr        net.Addr
	tls         *tls.Config
	cfg         *H2SCfg

	h2 *http2.Server
}

type Session struct {
	m       sync.RWMutex
	streams map[uint32]*H2Stream

	streamCh chan *H2Stream
	srv      *H2SServer
	framer   *http2.Framer
}

type H2Stream struct {
	id uint32
	s *Session

	hbuf *bytes.Buffer // HPACK encoder writes into this
	hdec *hpack.Decoder
	henc *hpack.Encoder

}

func Listen(ll net.Listener, tls *tls.Config, cfg *H2SCfg) *H2SServer {
	h2s := &H2SServer{
		ll: ll,
		tls: tls,
		cfg: cfg,
		h2: &http2.Server{},
	}

	go func() {
		str, err := h2s.ll.Accept()
		if err != nil {
			return
		}
		h2ss := &Session{
			srv: h2s,
			streams: map[uint32]*H2Stream{},
			streamCh: make(chan *H2Stream, 8),
		}

		go h2ss.handleStreamServer(str, h2s.tls)
	}()

	return h2s
}

func DialAddr(addr string, tls *tls.Config, cfg *H2SCfg) (*Session, error) {
	return nil, nil
}

func ListenAddr(addr string, tls *tls.Config, cfg *H2SCfg) (*H2SServer, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}

	return Listen(tcpConn, tls, cfg), nil
}

func (h2s *H2SServer) Close() {
	h2s.ll.Close()
	// TODO: close all open streams
}

func (h2s *Session) handleStreamServer(c net.Conn, tlsCfg *tls.Config) error {
	if tlsCfg != nil {
		tc := tls.Server(c, tlsCfg)
		err := tc.Handshake()
		if err != nil {
			log.Println("Error handling connection")
			return err
		}
		c = tc
	}

	// This requires a patched h2 impl - the default starts the promise in
	// half closed ( as required by the RFC ). Quic is symmetric.

	// The server implementation in H2 is good enough - main issue is
	// that push requires an active connection. It is also a bit complex,
	// but that's due to buffers. At this point it's better to reuse it.
	// Unlike H3, the HTTP layer is mixed, streams can't be separated.
	h2s.srv.h2.ServeConn(c, &http2.ServeConnOpts{
		Handler: h2s.srv.cfg.Handler,
	})
	return nil
}

func (h2s *Session) handleStreamClient(c net.Conn, tlsCfg *tls.Config) error {
	if tlsCfg != nil {
		tc := tls.Client(c, tlsCfg)
		err := tc.Handshake()
		if err != nil {
			log.Println("Error handling connection")
			return err
		}
		c = tc
	}
	// TODO: metrics
	// TODO: register mux

	h2f := http2.NewFramer(c, c)

	h2s.framer = h2f

	if h2s.srv.cfg.OnConnection != nil {
		h2s.srv.cfg.OnConnection(h2s)
	}

	var str *H2Stream
	for {
		f, err := h2f.ReadFrame()
		if err != nil {
			return nil
		}
		log.Println("H2 F: ", f.Header().Type)

		switch f := f.(type) {
		case *http2.SettingsFrame:
			// Sender acknoweldged the SETTINGS frame. No need to write
			// SETTINGS again.
			if f.IsAck() {
				break
			}
			if err := h2f.WriteSettingsAck(); err != nil {
				return nil
			}

		case *http2.PingFrame:

		case *http2.PushPromiseFrame:

		case *http2.GoAwayFrame: // not used for server, usually servers send GO_AWAY.

		case *http2.WindowUpdateFrame:
			str = h2s.stream(f.StreamID)

		case *http2.DataFrame:
			str = h2s.stream(f.StreamID)
			// TODO: flow control, see h2
			if f.Length > 0 {
				h2f.WriteWindowUpdate(f.StreamID, f.Length)
				h2f.WriteWindowUpdate(0, f.Length)

			}
			if f.StreamEnded() {

			}

		case *http2.RSTStreamFrame:
			str = h2s.stream(f.StreamID)

		case *http2.ContinuationFrame:
			str = h2s.stream(f.StreamID)
			if _, err := str.hdec.Write(f.HeaderBlockFragment()); err != nil {
				return nil
			}
			if f.FrameHeader.Flags&http2.FlagHeadersEndHeaders != 0 {
				h2s.handleStream(str)
			}

		case *http2.HeadersFrame:
			str := h2s.stream(f.StreamID)
			if _, err := str.hdec.Write(f.HeaderBlockFragment()); err != nil {
				return nil
			}
			if f.FrameHeader.Flags&http2.FlagHeadersEndHeaders != 0 {
				h2s.handleStream(str)
			}
		}
	}
	return nil
}

func (h2s *Session) handleStream(s *H2Stream) {

}


func (h2s *Session) stream(id uint32) *H2Stream {
	h2s.m.RLock()
	if ss, f := h2s.streams[id]; f {
		h2s.m.RUnlock()
		return ss
	}
	h2s.m.RUnlock()

	h2s.m.Lock()
	bb := &bytes.Buffer{}
	ss := &H2Stream{
		s: h2s,
		hbuf: bb,
		henc: hpack.NewEncoder(bb),
		hdec : hpack.NewDecoder(uint32(4<<10), func(hf hpack.HeaderField) {
		log.Println("Header: ", hf.Name, hf.Value)
	}),

	}
	h2s.streams[id] = ss
	h2s.m.Unlock()
	return ss
}

func (h2s *Session) AcceptStream(background context.Context) (*H2Stream, error) {

		return &H2Stream{}, nil
}

// In Quic, it's OpenStreamSync - quic returns a stream of bytes that is framed independently
// For H2, streams are opened using HEADER - using a http.Request to pass info
func (h2s *Session) OpenStreamSync(background context.Context) (*H2Stream, error) {

	return &H2Stream{}, nil
}

func (str *H2Stream) Close() error {
	return nil
}

func (str *H2Stream) WriteHeader(r *http.Request) (n int, err error) {
	panic("implement me")
}

func (str *H2Stream) Write(p []byte) (n int, err error) {
	panic("implement me")
}

func (str *H2Stream) ReadHeader(r *http.Request) (n int, err error) {
	panic("implement me")
}

func (str *H2Stream) Read(p []byte) (n int, err error) {
	panic("implement me")
}

