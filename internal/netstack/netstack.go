// Package netstack terminates captured TCP connections in a userspace
// TCP/IP stack (gVisor) and opens each one through the tunnel.
//
// Packets come from a Device (the utun interface on macOS). The stack runs
// in promiscuous mode with spoofing on, so it accepts connections to any
// destination routed to the device and answers as that destination. Each new
// connection is dialed through the tunnel *before* the handshake with the
// local application completes: a destination the agent can't reach gets a
// TCP reset, as it would on a real network, instead of accept-then-close.
//
// The wiring of a utun device to a gVisor link endpoint follows the approach
// of tun2socks (github.com/xjasonlyu/tun2socks, MIT).
package netstack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/md2k/subnet-tunnel/internal/relay"
)

// Device moves whole IP packets. Implementations may need headroom in front
// of each packet (utun's 4-byte address family header).
type Device interface {
	// Headroom is the number of bytes Read and Write need before the packet.
	Headroom() int
	// Read reads one packet into buf[Headroom():] and returns its length.
	Read(buf []byte) (int, error)
	// Write writes the packet at buf[Headroom():].
	Write(buf []byte) error
	// MTU is the largest packet the device carries.
	MTU() int
	Close() error
}

// Dialer opens the upstream connection, normally *tunnel.Client.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// ErrNoTunnel is what a Dialer returns (wrapped) while it has no tunnel,
// for example while reconnecting: the outage is reported once by whoever
// knows about it, so the failed connects are logged at debug level only.
var ErrNoTunnel = errors.New("no tunnel")

// Options configures New.
type Options struct {
	Logger      *slog.Logger  // nil: discard
	DialTimeout time.Duration // 0: 15s
	// TunAddr is the device's own address. Packets the system sends to it
	// (answers from a local listener to an app whose query went into the
	// device, like a DNS server redirected by the firewall) are handed
	// back to the system instead of the stack. Unset: no hand-back.
	TunAddr netip.Addr
	// Loop guard (see loopGuard): caps per destination (address and port)
	// on connections opening and open at once, and how long a destination
	// that hit one is refused. 0: the defaults.
	MaxOpening, MaxOpen int
	LoopHold            time.Duration
	// OnRefuse is told about each connection the loop guard refuses
	// (status counts them); nil: nothing.
	OnRefuse func(dst string)
}

const (
	nicID          = 1
	outQueueLen    = 1024
	maxInFlight    = 4096 // connections being dialed at once (all destinations)
	keepaliveIdle  = 60 * time.Second
	keepaliveIntvl = 30 * time.Second
	keepaliveCount = 9
)

// Stack is a running userspace stack attached to a device.
type Stack struct {
	s      *stack.Stack
	ep     *channel.Endpoint
	dev    Device
	dialer Dialer
	opts   Options
	guard  *loopGuard
	self   tcpip.Address // TunAddr, for the hand-back
	wmu    sync.Mutex    // Device.Write isn't safe for concurrent use
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// New starts a stack on dev and forwards every captured TCP connection
// through dialer. Close stops it and closes dev.
func New(dev Device, dialer Dialer, opts Options) (*Stack, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 15 * time.Second
	}
	if opts.MaxOpening == 0 {
		opts.MaxOpening = DefaultMaxOpening
	}
	if opts.MaxOpen == 0 {
		opts.MaxOpen = DefaultMaxOpen
	}
	if opts.LoopHold == 0 {
		opts.LoopHold = DefaultLoopHold
	}
	mtu := dev.MTU()
	if mtu <= 0 {
		return nil, fmt.Errorf("device MTU %d", mtu)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := tune(s); err != nil {
		s.Close()
		return nil, err
	}

	ep := channel.New(outQueueLen, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		s.Close()
		return nil, fmt.Errorf("create NIC: %s", err)
	}
	// Accept packets for any address and answer as that address.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		s.Close()
		return nil, fmt.Errorf("promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		s.Close()
		return nil, fmt.Errorf("spoofing: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	ctx, cancel := context.WithCancel(context.Background())
	st := &Stack{s: s, ep: ep, dev: dev, dialer: dialer, opts: opts, guard: newLoopGuard(opts.MaxOpening, opts.MaxOpen, opts.LoopHold), cancel: cancel}
	if opts.TunAddr.Is4() {
		st.self = tcpip.AddrFrom4(opts.TunAddr.As4())
	}
	fwd := tcp.NewForwarder(s, 0, maxInFlight, st.forward)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	st.wg.Add(2)
	go func() { defer st.wg.Done(); st.inbound(cancel) }()
	go func() { defer st.wg.Done(); st.outbound(ctx) }()
	return st, nil
}

// tune applies the TCP settings the October measurements were made with
// (tun2socks defaults): SACK, RACK loss detection, no Nagle delay, Reno.
func tune(s *stack.Stack) error {
	ttl := tcpip.DefaultTTLOption(64)
	if err := s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &ttl); err != nil {
		return fmt.Errorf("ipv4 ttl: %s", err)
	}
	if err := s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &ttl); err != nil {
		return fmt.Errorf("ipv6 ttl: %s", err)
	}
	sack := tcpip.TCPSACKEnabled(true)
	recovery := tcpip.TCPRACKLossDetection
	delay := tcpip.TCPDelayEnabled(false)
	cc := tcpip.CongestionControlOption("reno")
	send := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultSendBufferSize, Max: tcp.MaxBufferSize}
	recv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultReceiveBufferSize, Max: tcp.MaxBufferSize}
	for _, o := range []tcpip.SettableTransportProtocolOption{&sack, &recovery, &delay, &cc, &send, &recv} {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, o); err != nil {
			return fmt.Errorf("tcp option %T: %s", o, err)
		}
	}
	return nil
}

// forward runs in its own goroutine per connection attempt (gVisor starts
// it), so dialing here doesn't hold up other connections.
func (st *Stack) forward(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	log := st.opts.Logger.With("dst", dst)

	ok, warn, refused := st.guard.acquire(dst)
	if !ok {
		if st.opts.OnRefuse != nil {
			st.opts.OnRefuse(dst)
		}
		if warn {
			log.Warn("refusing connections to this destination for a while: too many at once, likely a routing loop (the target reaches it through this machine, and the routes send that back into the tunnel)",
				"for", st.opts.LoopHold, "refused", refused)
		}
		r.Complete(true)
		return
	}
	defer st.guard.release(dst)

	ctx, cancel := context.WithTimeout(context.Background(), st.opts.DialTimeout)
	up, err := st.dialer.DialContext(ctx, "tcp", dst)
	cancel()
	st.guard.dialed(dst)
	if err != nil {
		// A loop unwinding, the tunnel being down, or the same destination
		// failing again: debug.
		if !errors.Is(err, ErrNoTunnel) && !st.guard.looping(dst) && st.guard.reportFailure(dst) {
			log.Info("connect failed", "err", err)
		} else {
			log.Debug("connect failed", "err", err)
		}
		r.Complete(true) // reset: the app sees "connection refused"
		return
	}

	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		_ = up.Close()
		log.Debug("create endpoint failed", "err", terr)
		return
	}
	r.Complete(false)
	setKeepalive(ep)

	conn := gonet.NewTCPConn(&wq, ep)
	start := time.Now()
	log.Debug("connected")
	sent, recv := relay.Pipe(conn, up)
	log.Debug("closed", "sent", sent, "recv", recv, "dur", time.Since(start).Round(time.Millisecond))
}

func setKeepalive(ep tcpip.Endpoint) {
	ep.SocketOptions().SetKeepAlive(true)
	idle := tcpip.KeepaliveIdleOption(keepaliveIdle)
	intvl := tcpip.KeepaliveIntervalOption(keepaliveIntvl)
	_ = ep.SetSockOpt(&idle)
	_ = ep.SetSockOpt(&intvl)
	_ = ep.SetSockOptInt(tcpip.KeepaliveCountOption, keepaliveCount)
}

// inbound moves packets from the device into the stack.
func (st *Stack) inbound(stop context.CancelFunc) {
	defer stop()
	head, mtu := st.dev.Headroom(), st.dev.MTU()
	for {
		buf := make([]byte, head+mtu)
		n, err := st.dev.Read(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				st.opts.Logger.Debug("device read ended", "err", err)
			}
			return
		}
		if n <= 0 || n > mtu {
			continue
		}
		pkt := buf[head : head+n]
		var proto tcpip.NetworkProtocolNumber
		switch header.IPVersion(pkt) {
		case header.IPv4Version:
			if st.forSelf(pkt) {
				st.write(buf[:head+n])
				continue
			}
			proto = header.IPv4ProtocolNumber
		case header.IPv6Version:
			proto = header.IPv6ProtocolNumber
		default:
			continue
		}
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		st.ep.InjectInbound(proto, pb)
		pb.DecRef()
	}
}

// outbound moves packets from the stack to the device.
func (st *Stack) outbound(ctx context.Context) {
	head := st.dev.Headroom()
	for {
		pb := st.ep.ReadContext(ctx)
		if pb == nil {
			return
		}
		view := pb.ToView()
		pb.DecRef()
		buf := make([]byte, head+view.Size())
		copy(buf[head:], view.AsSlice())
		view.Release()
		st.write(buf)
	}
}

// forSelf reports whether an IPv4 packet from the system is addressed to
// the device's own address. The system sends those out of the device
// because its address is also the point-to-point peer.
func (st *Stack) forSelf(pkt []byte) bool {
	return st.self.Len() > 0 && len(pkt) >= header.IPv4MinimumSize && header.IPv4(pkt).DestinationAddress() == st.self
}

// write sends one packet (after the device's headroom) to the system.
func (st *Stack) write(buf []byte) {
	st.wmu.Lock()
	err := st.dev.Write(buf)
	st.wmu.Unlock()
	if err != nil {
		st.opts.Logger.Debug("device write failed", "err", err)
	}
}

// Close stops the stack, closes the device and waits for the packet loops.
// Connections in flight are torn down.
func (st *Stack) Close() error {
	var err error
	st.once.Do(func() {
		err = st.dev.Close()
		st.cancel()
		st.ep.Close()
		st.s.Close()
		st.wg.Wait()
		st.s.Wait()
	})
	return err
}
