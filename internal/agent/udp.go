package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"

	"github.com/md2k/subnet-tunnel/internal/proto"
	"github.com/md2k/subnet-tunnel/internal/relay"
)

const (
	// udpSocketBuffer is the receive buffer asked for a flow's socket (Linux
	// gives at most net.core.rmem_max, doubled).
	udpSocketBuffer = 4 << 20
	// udpQueueBytes bounds what was read from the socket and isn't in the
	// stream yet (the stream's window, as for TCP).
	udpQueueBytes = 4 << 20
	// datagramOverhead is what a queued datagram costs on top of its bytes.
	datagramOverhead = 64
	// udpErrorStreak read errors in a row, with no datagram between them,
	// end the flow: the socket is broken, not one datagram.
	udpErrorStreak = 1000
)

// handleUDP relays one UDP flow: datagrams from the stream go to req.Addr
// from a socket of the agent's own, and what comes back goes into the
// stream, until subtun closes the stream (the flow went idle) or the
// session ends. A reader drains the socket into a queue and a writer feeds
// the stream from it, so a slow stream doesn't overflow the socket. An error
// for one datagram (the ICMP errors a connected socket reports: port, host or
// network unreachable, too big for the path) doesn't end the flow: it's
// counted, and the first of each kind is logged.
func handleUDP(ctx context.Context, st *smux.Stream, req proto.Request, cfg Config) {
	log := cfg.Logger.With("stream", st.ID(), "addr", req.Addr)
	dctx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	c, err := cfg.Dialer.DialContext(dctx, "udp", req.Addr)
	cancel()
	if err != nil {
		log.Debug("udp dial failed", "err", err)
		_ = proto.WriteResponse(st, proto.Response{Status: StatusFor(err), Msg: err.Error()})
		return
	}
	defer c.Close()
	if rb, ok := c.(interface{ SetReadBuffer(int) error }); ok {
		_ = rb.SetReadBuffer(udpSocketBuffer)
	}
	if err := proto.WriteResponse(st, proto.Response{Status: proto.StatusOK}); err != nil {
		return
	}

	start := time.Now()
	var (
		errs    relay.Errors
		once    sync.Once
		reason  string // why the flow ended: the first to say wins
		closing atomic.Bool
		up      int
		down    int // the writer's, read after it's done
	)
	end := func(r string) { once.Do(func() { reason = r }) }
	note := func(dir string, err error) {
		if errs.Add(dir, err) {
			log.Debug("udp flow error", "dir", dir, "err", err)
		}
	}
	q := newDatagramQueue(udpQueueBytes)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // the target's answers into the queue
		defer wg.Done()
		defer q.Close()
		buf := make([]byte, proto.MaxDatagramLen)
		streak := 0
		for {
			n, err := c.Read(buf)
			if err != nil {
				if closing.Load() || errors.Is(err, net.ErrClosed) {
					return
				}
				note("read", err)
				if streak++; streak >= udpErrorStreak {
					end(fmt.Sprintf("%d read errors in a row", streak))
					return
				}
				continue
			}
			streak = 0
			q.Push(append([]byte(nil), buf[:n]...))
		}
	}()
	go func() { // the queue into the stream
		defer wg.Done()
		defer st.Close() // if the reader ended the flow, subtun hears of it
		for {
			d, ok := q.Pop()
			if !ok {
				return
			}
			if err := proto.WriteDatagram(st, d); err != nil {
				end("stream write: " + err.Error())
				return
			}
			down += len(d)
		}
	}()

	buf := make([]byte, proto.MaxDatagramLen)
	for {
		n, err := proto.ReadDatagram(st, buf)
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				end("closed by subtun")
			case ctx.Err() != nil:
				end("session ended")
			default:
				end("stream read: " + err.Error())
			}
			break
		}
		if _, err := c.Write(buf[:n]); err != nil {
			note("write", err)
			continue
		}
		up += n
	}
	closing.Store(true)
	_ = c.Close()
	_ = st.Close() // a writer waiting on the stream's window gives up
	wg.Wait()
	attrs := []any{"reason", reason, "up", up, "down", down, "dur", time.Since(start).Round(time.Millisecond)}
	if d := q.Dropped(); d > 0 {
		attrs = append(attrs, "dropped", d)
	}
	if s := errs.String(); s != "" {
		attrs = append(attrs, "errors", s)
	}
	log.Debug("udp flow closed", attrs...)
}

// datagramQueue holds datagrams between a flow's socket reader and its
// stream writer, up to a byte limit (each costs its length plus
// datagramOverhead, so empty ones count too). Push never blocks: a full
// queue drops the datagram, as a full socket buffer would.
type datagramQueue struct {
	mu      sync.Mutex
	cond    sync.Cond
	items   [][]byte
	size    int
	limit   int
	dropped int
	closed  bool
}

func newDatagramQueue(limit int) *datagramQueue {
	q := &datagramQueue{limit: limit}
	q.cond.L = &q.mu
	return q
}

// Push queues d; false if it was dropped (full) or the queue is closed.
func (q *datagramQueue) Push(d []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	cost := len(d) + datagramOverhead
	if q.size+cost > q.limit {
		q.dropped++
		return false
	}
	q.items = append(q.items, d)
	q.size += cost
	q.cond.Signal()
	return true
}

// Pop waits for a datagram; false once the queue is closed and empty.
func (q *datagramQueue) Pop() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return nil, false
	}
	d := q.items[0]
	q.items[0] = nil
	q.items = q.items[1:]
	q.size -= len(d) + datagramOverhead
	return d, true
}

// Close wakes Pop; what's queued can still be popped.
func (q *datagramQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.cond.Broadcast()
}

// Dropped is the number of datagrams dropped because the queue was full.
func (q *datagramQueue) Dropped() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}
