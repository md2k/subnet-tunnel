package cli

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/md2k/subnet-tunnel/internal/meter"
	"github.com/md2k/subnet-tunnel/internal/netstack"
)

// router sends each captured connection to the tunnel whose route matches
// its destination most specifically (several tunnels). Its table holds the
// routes on the utun, so every destination that arrives has an entry; a
// miss happens only while routes change.
type router struct {
	table atomic.Pointer[[]routeEntry]
}

type routeEntry struct {
	prefix netip.Prefix
	tunnel meter.Dialer // the profile's tunnel, counted
	i      int          // the profile
}

// set replaces the table.
func (r *router) set(entries []routeEntry) {
	t := slices.Clone(entries)
	slices.SortStableFunc(t, func(a, b routeEntry) int { return cmp.Compare(b.prefix.Bits(), a.prefix.Bits()) })
	r.table.Store(&t)
}

// pick returns the tunnel for a destination address.
func (r *router) pick(a netip.Addr) meter.Dialer {
	if e := r.entry(a); e != nil {
		return e.tunnel
	}
	return nil
}

// pickIndex returns the profile that carries a destination address, -1 if
// none.
func (r *router) pickIndex(a netip.Addr) int {
	if e := r.entry(a); e != nil {
		return e.i
	}
	return -1
}

func (r *router) entry(a netip.Addr) *routeEntry {
	t := r.table.Load()
	if t == nil {
		return nil
	}
	for k := range *t {
		if (*t)[k].prefix.Contains(a) {
			return &(*t)[k]
		}
	}
	return nil
}

// DialContext implements netstack.Dialer.
func (r *router) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	t := r.pick(ap.Addr().Unmap())
	if t == nil {
		return nil, fmt.Errorf("no tunnel routes %s (%w)", ap.Addr(), netstack.ErrNoTunnel)
	}
	return t.DialContext(ctx, network, addr)
}
