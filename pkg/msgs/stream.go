package msgs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

var (
	// createBuffer to get a buffer. Inspired from caddy.
	// See PooledIOCopy for example
	bufferPoolCopy = sync.Pool{New: func() interface{} {
		return make([]byte, 0, 8*1024)
	}}
)

// Client or server event-stream connection.
// Useful for debugging and sending messages to old browsers.
// This is one of the simplest protocols.

type EventStreamConnection struct {
	MsgConnection
}

// Websocket stream - each frame is a message.
// Currently using a special protocol - derived from 'disaster radio' - since
// I'm testing LoRA and related IoT protocols.
// Will eventually use protobufs (after I fix the firmware)
func (gate *Gateway) websocketStream(conn *websocket.Conn) {
	data := make([]byte, 4096)
	fr, err := conn.NewFrameReader()
	if err != nil {
		log.Println("Websocket ", err)
		return
	}
	fw, _ := conn.NewFrameWriter(conn.PayloadType)
	go func() {
		eventStream(conn.Request().Context(), conn.Request().RemoteAddr, func(ev *Message) error {
			bo := bytes.Buffer{}
			ba := ev.MarshalJSON()
			bo.Write([]byte{0, 1, 'c', '|'})
			bo.Write(ba)
			_, err := fw.Write(bo.Bytes())
			if err != nil {
				return err
			}
			return nil
		})
	}()
	for {
		n, err := fr.Read(data)
		if err != nil {
			log.Println("Websocket ", err)
			return
		}
		if data[2] != '!' {
			fw.Write([]byte{data[0], data[1], '!'})
		}

		from := ""
		body := ""
		if data[2] == 'c' && data[3] == '|' {
			if data[4] == '<' {
				msgb := string(data[5:n])
				uidEnd := strings.Index(msgb, ">")
				from = msgb[0:uidEnd]
				body = msgb[uidEnd:]
			} else {
				body = string(data[4:n])
				from = ""
			}
			// <from> cmd params ?
			log.Printf("WS: %s %s\n", from, body)
			gate.mux.SendMessage(&Message{
				Id:         fmt.Sprintf("%X%X", data[0], data[1]),
				To:         "/" + body,
				Subject:    "",
				Path:       nil,
				From:       from,
				Data:       nil,
				Meta:       nil,
				Connection: nil,
				Topic:      "",
			})
			log.Printf("WS: %X%X %s\n", data[0], data[1], string(data[2:n]))
		} else {
			msgb := string(data[3:n])
			log.Printf("WS: %X%X %s\n", data[0], data[1], msgb)
		}

	}

}

// Used to receive (subscribe) to messages, using HTTP streaming protocol.
//
// TODO: pass the list of subscriptions, filter, 'start' message
func (gate *Gateway) HTTPHandlerEventStream(w http.ResponseWriter, req *http.Request) {
	req.Header.Get("last-event-id")
	req.Header.Get("accept") // should be text/event-stream for event source, otherwise it's a GET

	h := w.Header()
	h.Add("Content-Type", "text/event-stream")
	h.Add("Cache-Control", "no-cache")

	w.WriteHeader(200)

	// Need to send an empty message first ( for strange reasons ?)
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", "{}")

	eventStream(req.Context(), req.RemoteAddr, func(ev *Message) error {
		ba := ev.MarshalJSON()

		// TODO: id, set type in event: header ( or test if message is not required )
		//
		_, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(ba))
		if err != nil {
			return err
		}
		w.(http.Flusher).Flush()
		return nil
	})
}

// Used to receive (subscribe) to messages, as well as send messages.
//
// TODO: pass the list of subscriptions, filter, 'start' message
func eventStream(reqContext context.Context, req string, sender func(ev *Message) error) {

	ch := make(chan *Message, 10)

	id := "http-" + req
	mc := &MsgConnection{
		SubscriptionsToSend: []string{"*"},
		SendMessageToRemote: func(ev *Message) error {
			ch <- ev
			return nil
		},
	}

	// All messages sent to the channel
	DefaultMux.AddHandler("*", HandlerCallbackFunc(func(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
		ch <- NewMessage(cmdS, meta).SetDataJSON(data)
	}))

	DefaultMux.AddConnection(id, mc)

	log.Println("DM HTTP EVENT STREAM ", req)

	defer func() {
		DefaultMux.Gate.RemoveConnection(id, mc)
		log.Println("DM HTTP EVENT STREAM CLOSE ", req)
	}()

	// source.addEventListener('add', addHandler, false);
	// event: add
	// data: LINE
	//
	ctx := reqContext
	for {
		select {
		case ev := <-ch:
			sender(ev)
		case <-ctx.Done():
			return
		}
	}
}

func (gate *Gateway) MonitorNode(hc *http.Client, idhex *net.IPAddr) error {
	t0 := time.Now()
	url := "http://127.0.0.1:5227/debug/eventss"
	//p := "/"
	if idhex != nil {
		//for _, pp := range path {
		//	p = p + pp + "/"
		//}
		//p = p + idhex + "/"
		//url = "http://127.0.0.1:5227/dm" + p + "127.0.0.1:5227/debug/eventss"
		url = "http://" + idhex.String() + ":5227/debug/eventss"
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	ctx, _ := context.WithTimeout(context.Background(), 600*time.Second)
	req = req.WithContext(ctx)
	res, err := hc.Do(req)
	if err != nil || res.StatusCode != 200 {
		log.Println("WATCH_ERR1", url, err, time.Since(t0), res)
		return err
	}

	rd := bufio.NewReader(res.Body)

	for {
		l, _, err := rd.ReadLine()
		if err != nil {
			if err.Error() != "EOF" {
				log.Println("WATCH_ERR2", url, err)
				return err
			} else {
				log.Println("WATCH_CLOSE", url, time.Since(t0), err)
				return nil
			}
		}
		ls := string(l)
		if ls == "" || ls == "event: message" {
			continue
		}

		if strings.HasPrefix("data:", ls) {
			ls = ls[5:]

			log.Println(idhex, ls)

		} else {

			log.Println(idhex, ls)
		}
	}
}



// Process a stream of messages - framing, parsing.
// Current implementation: 2-byte prefix,
//
// WIP: other formats
// The format is TLV or delimited, based on the first byte.
//
// 0 NNNN - TLV, payload expected to be a proto ( this is the format of streaming gRPC, so it is possible
//   to use it directly in a handler for efficient, complexity-free gRPC)
//
// 1 NNNN - not used, it's gRPC compressed message.
//
// '{' - delimited JSON, \0
//
// \n - delimited JSON, \n
//
// 2 NNNNN - TLV, payload is JSON.
//
// 'event:' - SSE, frame delim: \n\n or \r\n\r\n

// NATS: text based
// PUB and MSG have payload,
// PUB subject reply-to bytecount\r\nCOUNTBYTES\r\n
// subscription id - associate message with SUB subscription
//
// first line: METHOD param:val ...
// 'subject', '

type Stream struct {
	Reader *bufio.Reader

	delim byte

	// For UDS: based on associated creds.
	// For TLS: cert public key
	RemoteID string

	Writer *io.Writer
}


//type PacketReader struct {
//	r   io.Reader
//	buf []byte
//
//	tagSize int
//	lenSize int
//
//	start int
//	end   int
//
//	off int
//	cap int
//}
//
//// WIP
//func NewPacketReaderTLV(r io.Reader, tagSize, lenSize int) *PacketReader {
//	pr := &PacketReader{
//		r:   r,
//		buf: bufferPoolCopy.Get().([]byte),
//	}
//	pr.cap = cap(pr.buf)
//	return pr
//}
//
//// WIP: Read a delimited packet from the stream. The returned slice is owned by
//// the reader
//func (pr *PacketReader) MessageRead() ([]byte, int, error) {
//	for {
//		n, err := pr.r.Read(pr.buf[pr.end:])
//		if err != nil {
//			bufferPoolCopy.Put(pr.buf)
//			return nil, 0, err
//		}
//		pr.end += n
//
//		currentSize := pr.end - pr.start
//		if currentSize < pr.tagSize+pr.lenSize {
//			continue
//		}
//		var expSize int
//		switch pr.lenSize {
//		case 2:
//			expSize = int(binary.BigEndian.Uint16(pr.buf[pr.start+pr.tagSize:]))
//		case 4:
//			expSize = int(binary.BigEndian.Uint32(pr.buf[pr.start+pr.tagSize:]))
//		}
//		if expSize > currentSize {
//			continue
//		}
//
//		packet := pr.buf[pr.start+pr.tagSize+pr.lenSize : pr.start+expSize]
//
//		// Deal with the bytes after packet end. If less then a packet - move.
//
//		pr.start = pr.start + expSize
//
//		return packet, expSize, nil
//	}
//}

var Debug = false

// Send a binary packet, with len prefix.
// Currently used in the UDS mapping.
func SendFrameLenBinary(con io.Writer, data ...[]byte) (int, error) {
	dlen := 0
	for _, d := range data {
		if d == nil {
			continue
		}
		dlen += len(d)
	}

	msg := make([]byte, dlen+5)

	off := 5
	for _, d := range data {
		if d == nil {
			continue
		}
		copy(msg[off:], d)
		off += len(d)
	}
	msg[0] = 0
	binary.LittleEndian.PutUint32(msg[1:], uint32(dlen))

	if con != nil {
		_, err := con.Write(msg)
		if Debug {
			log.Println("Frame N2A: ", len(data), data[0])
		}
		return len(data), err
	}
	return 0, nil
}

// Parse a message.
// Currently used in the UDS mapping, using a HTTP1-like text format
func ParseMessage(data []byte, mtype int) (cmd string, meta map[string]string, outd []byte, end int) {
	start := 0
	n := len(data)
	meta = map[string]string{}

	endLine := bytes.IndexByte(data[start:n], '\n')

	if endLine < 0 { // short message, old style
		endLine = n
		cmd = string(data[0:n])
		log.Println("UDS: short", cmd)
		return
	}
	cmd = string(data[0:endLine])
	if Debug {
		log.Println("UDS: cmd", n, endLine, cmd)
	}

	endLine++
	for {
		nextLine := bytes.IndexByte(data[endLine:n], '\n')
		if nextLine == -1 {
			break // shouldn't happen - \n\n expected
		}
		if nextLine == 0 {
			endLine++ // end of headers
			break
		}
		kv := string(data[endLine : endLine+nextLine])
		kvp := strings.SplitN(kv, ":", 2)
		if len(kvp) != 2 {
			continue
		}
		meta[kvp[0]] = kvp[1]
		if Debug {
			log.Println("UDS: key", kvp)
		}
		endLine += nextLine
		endLine++
	}

	if endLine < n {
		outd = data[endLine:n]
	}

	return
}
