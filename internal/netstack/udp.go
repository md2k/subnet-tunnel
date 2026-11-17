package netstack

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/md2k/subnet-tunnel/internal/proto"
)

// A UDP flow (an application's address and port to a destination) goes
// through the tunnel as one stream while datagrams pass; after this long
// with none either way it's closed (the agent's socket with it).
const (
	udpIdle    = 2 * time.Minute
	udpIdleDNS = 15 * time.Second // port 53: a query and its answer
)

// forwardUDP takes the first datagram of a new flow. gVisor calls it in the
// packet path, so the endpoint is made here and the dial happens in a
// goroutine; datagrams arriving meanwhile wait in the endpoint's queue.
func (st *Stack) forwardUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	key := "udp " + dst // the loop guard counts UDP flows apart from TCP
	ok, warn, refused := st.guard.acquire(key)
	if !ok {
		if st.opts.OnRefuse != nil {
			st.opts.OnRefuse(key)
		}
		if warn {
			st.opts.Logger.Warn("refusing UDP to this destination for a while: too many flows at once, likely a routing loop (the target reaches it through this machine, and the routes send that back into the tunnel)",
				"dst", dst, "for", st.opts.LoopHold, "refused", refused)
		}
		return true // dropped
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		st.guard.release(key)
		st.opts.Logger.Debug("create UDP endpoint failed", "dst", dst, "err", err)
		return true
	}
	idle := st.opts.UDPIdle
	switch {
	case idle > 0:
	case id.LocalPort == 53:
		idle = udpIdleDNS
	default:
		idle = udpIdle
	}
	go st.relayUDP(gonet.NewUDPConn(&wq, ep), key, dst, idle)
	return true
}

// relayUDP opens the flow through the tunnel and copies datagrams both ways
// until it has been idle for idle, or either side ends.
func (st *Stack) relayUDP(conn *gonet.UDPConn, key, dst string, idle time.Duration) {
	defer st.guard.release(key)
	defer conn.Close()
	log := st.opts.Logger.With("dst", dst, "proto", "udp")

	ctx, cancel := context.WithTimeout(context.Background(), st.opts.DialTimeout)
	up, err := st.dialer.DialContext(ctx, "udp", dst)
	cancel()
	st.guard.dialed(key)
	if err != nil {
		if !errors.Is(err, ErrNoTunnel) && !st.guard.looping(key) && st.guard.reportFailure(key) {
			log.Info("UDP flow failed", "err", err)
		} else {
			log.Debug("UDP flow failed", "err", err)
		}
		return
	}
	defer up.Close()

	var last atomic.Int64 // unix nanoseconds of the latest datagram, either way
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	start := time.Now()
	var sent, recv atomic.Int64
	done := make(chan struct{})
	go func() { // the agent's datagrams to the application
		defer close(done)
		buf := make([]byte, proto.MaxDatagramLen)
		for {
			n, err := up.Read(buf)
			if err != nil {
				_ = conn.Close()
				return
			}
			touch()
			if _, err := conn.Write(buf[:n]); err == nil {
				recv.Add(int64(n))
			}
		}
	}()
	buf := make([]byte, proto.MaxDatagramLen)
	deadline := time.Now().Add(idle)
	for {
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if next := time.Unix(0, last.Load()).Add(idle); time.Until(next) > 0 {
					deadline = next // the other way was busy
					continue
				}
			}
			break
		}
		touch()
		deadline = time.Now().Add(idle)
		if _, err := up.Write(buf[:n]); err != nil {
			break
		}
		sent.Add(int64(n))
	}
	_ = up.Close()
	<-done
	log.Debug("closed", "sent", sent.Load(), "recv", recv.Load(), "dur", time.Since(start).Round(time.Millisecond))
}
