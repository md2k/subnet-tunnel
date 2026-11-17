// Package proto is the wire format between subtun and its agent.
//
// The agent starts by writing one hello line on its stdout. After that the
// carrier (exec stdio, SSH channel, ...) runs an smux session. Every smux
// stream opened by subtun carries one Request and the agent answers with one
// Response. For CmdConnectTCP the stream then is a raw byte pipe to the
// connection the agent opened; for CmdDNS it carries one query and one
// answer; for CmdUDP, datagrams both ways.
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/xtaci/smux"
)

// Version is the protocol version. Bump it on any incompatible change to the
// hello line, Request, Response or MuxConfig.
const Version = 1

// HelloPrefix starts the agent's hello line.
const HelloPrefix = "subtun-agent"

// MaxHelloLen bounds the hello line so a misbehaving remote can't make the
// client buffer without limit.
const MaxHelloLen = 256

const (
	// MaxAddrLen bounds Request.Addr ("host:port"; DNS names are <= 253 bytes).
	MaxAddrLen = 512
	// MaxMsgLen bounds Response.Msg; longer messages are truncated.
	MaxMsgLen = 512
)

// Cmd is what a Request asks the agent to do.
type Cmd byte

// Commands.
const (
	CmdConnectTCP Cmd = 1
	// CmdDNS sends one DNS query to a resolver in the target. Addr names the
	// resolver; ResolverSystem means the target's own (its /etc/resolv.conf).
	// After the request subtun writes the query, framed by WriteDNS; on
	// StatusOK the agent writes the answer the same way and closes the stream.
	CmdDNS Cmd = 2
	// CmdUDP relays the datagrams of one UDP flow: the agent sends them to
	// Addr from a socket of its own and returns what comes back. After
	// StatusOK both sides write datagrams framed by WriteDatagram, until
	// subtun closes the stream (the flow went idle) or the session ends.
	CmdUDP Cmd = 3
)

// MaxDatagramLen bounds a framed datagram: a UDP payload fits in it.
const MaxDatagramLen = 65535

// ResolverSystem as the Addr of a CmdDNS request: the target's own resolver.
const ResolverSystem = "-"

// DNS messages on a stream are framed like DNS over TCP: a uint16 length,
// then the message.
const (
	MinDNSLen = 12 // the header
	MaxDNSLen = 65535
)

// Status is the agent's answer to a Request.
type Status byte

// Statuses.
const (
	StatusOK          Status = 0
	StatusFailure     Status = 1
	StatusRefused     Status = 2
	StatusUnreachable Status = 3
	StatusTimeout     Status = 4
	StatusDNS         Status = 5
	StatusBadRequest  Status = 6
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusFailure:
		return "failure"
	case StatusRefused:
		return "connection refused"
	case StatusUnreachable:
		return "unreachable"
	case StatusTimeout:
		return "timeout"
	case StatusDNS:
		return "name resolution failed"
	case StatusBadRequest:
		return "bad request"
	default:
		return "status " + strconv.Itoa(int(s))
	}
}

// MuxConfig is the smux configuration both ends must use. Version 2 gives
// per-stream flow control; the stream window has to cover bandwidth × RTT or
// a single connection is capped at window/RTT.
func MuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.MaxFrameSize = 65535
	c.MaxStreamBuffer = 4 << 20
	c.MaxReceiveBuffer = 32 << 20
	c.KeepAliveInterval = 10 * time.Second
	c.KeepAliveTimeout = 30 * time.Second
	return c
}

// Hello is what the agent announces before the multiplexer starts.
type Hello struct {
	Proto   int
	Version string // agent build version, informational
	SHA256  string // hex sha256 of the agent binary, "-" if unknown
}

// Line renders the hello line, including the trailing newline.
func (h Hello) Line() string {
	sum := h.SHA256
	if sum == "" {
		sum = "-"
	}
	return fmt.Sprintf("%s %d %s %s\n", HelloPrefix, h.Proto, field(h.Version), sum)
}

func field(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\n") {
		return "-"
	}
	return s
}

// ParseHello parses a hello line (with or without the trailing newline).
func ParseHello(line string) (Hello, error) {
	f := strings.Fields(line)
	if len(f) != 4 || f[0] != HelloPrefix {
		return Hello{}, fmt.Errorf("not a subtun agent hello: %q", truncate(line, 80))
	}
	p, err := strconv.Atoi(f[1])
	if err != nil {
		return Hello{}, fmt.Errorf("bad protocol version in hello: %q", f[1])
	}
	h := Hello{Proto: p, Version: f[2], SHA256: f[3]}
	if h.SHA256 == "-" {
		h.SHA256 = ""
	}
	return h, nil
}

// ReadHello reads the hello line one byte at a time, so nothing after the
// newline is consumed: those bytes belong to the multiplexer.
func ReadHello(r io.Reader) (Hello, error) {
	var b [1]byte
	line := make([]byte, 0, 64)
	for len(line) < MaxHelloLen {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			if len(line) > 0 {
				return Hello{}, fmt.Errorf("reading agent hello after %q: %w", truncate(string(line), 80), err)
			}
			return Hello{}, fmt.Errorf("reading agent hello: %w", err)
		}
		if b[0] == '\n' {
			return ParseHello(string(line))
		}
		line = append(line, b[0])
	}
	return Hello{}, fmt.Errorf("agent hello longer than %d bytes: %q", MaxHelloLen, truncate(string(line), 80))
}

// Request opens a connection through the agent.
type Request struct {
	Cmd  Cmd
	Addr string // "host:port"; host may be a name, resolved on the agent side
}

// Errors returned while decoding.
var (
	ErrVersion = errors.New("unsupported protocol version")
	ErrAddr    = errors.New("address empty or too long")
)

// WriteRequest encodes r as: version, cmd, uint16 length, addr.
func WriteRequest(w io.Writer, r Request) error {
	if len(r.Addr) == 0 || len(r.Addr) > MaxAddrLen {
		return ErrAddr
	}
	buf := make([]byte, 0, 4+len(r.Addr))
	buf = append(buf, Version, byte(r.Cmd))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(r.Addr)))
	buf = append(buf, r.Addr...)
	_, err := w.Write(buf)
	return err
}

// ReadRequest decodes a Request written by WriteRequest.
func ReadRequest(r io.Reader) (Request, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Request{}, err
	}
	if hdr[0] != Version {
		return Request{}, fmt.Errorf("%w: %d", ErrVersion, hdr[0])
	}
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	if n == 0 || n > MaxAddrLen {
		return Request{}, ErrAddr
	}
	addr := make([]byte, n)
	if _, err := io.ReadFull(r, addr); err != nil {
		return Request{}, err
	}
	return Request{Cmd: Cmd(hdr[1]), Addr: string(addr)}, nil
}

// Response is the agent's answer to a Request.
type Response struct {
	Status Status
	Msg    string // error detail when Status != StatusOK
}

// WriteResponse encodes r as: status, uint16 length, msg.
func WriteResponse(w io.Writer, r Response) error {
	msg := truncate(r.Msg, MaxMsgLen)
	buf := make([]byte, 0, 3+len(msg))
	buf = append(buf, byte(r.Status))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(msg)))
	buf = append(buf, msg...)
	_, err := w.Write(buf)
	return err
}

// ReadResponse decodes a Response written by WriteResponse.
func ReadResponse(r io.Reader) (Response, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Response{}, err
	}
	n := int(binary.BigEndian.Uint16(hdr[1:]))
	if n > MaxMsgLen {
		return Response{}, fmt.Errorf("response message too long: %d", n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return Response{}, err
	}
	return Response{Status: Status(hdr[0]), Msg: string(msg)}, nil
}

// WriteDNS writes one framed DNS message.
func WriteDNS(w io.Writer, msg []byte) error {
	if len(msg) < MinDNSLen || len(msg) > MaxDNSLen {
		return fmt.Errorf("DNS message of %d bytes", len(msg))
	}
	buf := make([]byte, 0, 2+len(msg))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(msg)))
	buf = append(buf, msg...)
	_, err := w.Write(buf)
	return err
}

// ReadDNS reads one framed DNS message.
func ReadDNS(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < MinDNSLen {
		return nil, fmt.Errorf("DNS message of %d bytes", n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// WriteDatagram writes one datagram, framed by a uint16 length (0 is a
// valid, empty datagram), in a single write.
func WriteDatagram(w io.Writer, b []byte) error {
	if len(b) > MaxDatagramLen {
		return fmt.Errorf("datagram of %d bytes", len(b))
	}
	buf := make([]byte, 0, 2+len(b))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(b)))
	buf = append(buf, b...)
	_, err := w.Write(buf)
	return err
}

// ReadDatagram reads one framed datagram into buf (MaxDatagramLen bytes is
// always enough) and returns its length; a longer one is an error.
func ReadDatagram(r io.Reader, buf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(buf) {
		return 0, fmt.Errorf("datagram of %d bytes for a %d-byte buffer", n, len(buf))
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

// DialError is a failed Request as reported by the agent.
type DialError struct {
	Addr   string
	Status Status
	Msg    string
}

func (e *DialError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("agent: dial %s: %s", e.Addr, e.Status)
	}
	return fmt.Sprintf("agent: dial %s: %s (%s)", e.Addr, e.Status, e.Msg)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
