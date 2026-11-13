// Package fake provides drivers that record what they were asked to do,
// for testing code that uses internal/platform without root.
package fake

import (
	"fmt"
	"net/netip"
	"os"
	"sync"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

// Drivers implements every platform driver and records each call in order.
type Drivers struct {
	// Failures to inject, set before use.
	CreateErr error
	AddErr    map[netip.Prefix]error
	ApplyErr  error
	Busy      bool // firewall rules already loaded (left by an earlier session)
	// DNSCache adds a DNS cache driver, recorded as "flush dns cache". Off
	// by default, so call sequences of tests that don't care stay short.
	DNSCache bool

	mu    sync.Mutex
	calls []string
	n     int
	token string
}

// Platform returns d as a platform.Drivers.
func (d *Drivers) Platform() platform.Drivers {
	p := platform.Drivers{Tun: d, Routes: d, Firewall: firewall{d}}
	if d.DNSCache {
		p.DNSCache = dnsCache{d}
	}
	return p
}

type dnsCache struct{ d *Drivers }

func (c dnsCache) Flush() error {
	c.d.record("flush dns cache")
	return nil
}

// Calls returns the calls so far, e.g. "create utun0 9000 198.18.249.1",
// "add 10.0.0.0/8 utun0", "release utun0", "delete 10.0.0.0/8 utun0",
// "close utun0", "firewall dns [192.168.1.1] 53530 53531", "flush".
func (d *Drivers) Calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

func (d *Drivers) record(format string, args ...any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, fmt.Sprintf(format, args...))
}

// Create implements platform.Tun with a pipe standing in for the interface.
func (d *Drivers) Create(mtu int, addr netip.Addr) (platform.TunDevice, error) {
	if d.CreateErr != nil {
		return nil, d.CreateErr
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	name := fmt.Sprintf("utun%d", d.n)
	d.n++
	d.mu.Unlock()
	d.record("create %s %d %s", name, mtu, addr)
	return &device{d: d, name: name, r: r, w: w}, nil
}

// Add implements platform.Routes.
func (d *Drivers) Add(p netip.Prefix, iface string) error {
	if err := d.AddErr[p]; err != nil {
		return err
	}
	d.record("add %s %s", p, iface)
	return nil
}

// Delete implements platform.Routes.
func (d *Drivers) Delete(p netip.Prefix, iface string) error {
	d.record("delete %s %s", p, iface)
	return nil
}

type device struct {
	d    *Drivers
	name string
	r, w *os.File
}

func (v *device) Name() string   { return v.name }
func (v *device) File() *os.File { return v.r }

func (v *device) Release() error {
	v.d.record("release %s", v.name)
	return v.r.Close()
}

func (v *device) Close() error {
	v.d.record("close %s", v.name)
	_ = v.r.Close()
	return v.w.Close()
}

// firewall implements platform.Firewall (a separate type: Drivers already
// has the Routes methods).
type firewall struct{ d *Drivers }

func (f firewall) Apply(r platform.Rules) error {
	if f.d.ApplyErr != nil {
		return f.d.ApplyErr
	}
	desc := "firewall"
	if r.Empty() {
		desc += " none"
	}
	if r.DNS != nil {
		desc += fmt.Sprintf(" dns %v %d %d", r.DNS.Servers, r.DNS.ListenPort, r.DNS.BypassPort)
	}
	if len(r.DNSBlock) > 0 {
		desc += fmt.Sprintf(" dnsblock %v", r.DNSBlock)
	}
	if k := r.KillSwitch; k != nil {
		iface := k.TunIface
		if iface == "" {
			iface = "-"
		}
		desc += fmt.Sprintf(" guard %s %v", iface, k.Prefixes)
	}
	if r.BlockIPv6 {
		desc += " ipv6"
	}
	f.d.mu.Lock()
	if f.d.token == "" {
		f.d.token = "fake-token"
	}
	f.d.mu.Unlock()
	f.d.record("%s", desc)
	return nil
}

func (f firewall) Flush() error {
	f.d.mu.Lock()
	f.d.token = ""
	f.d.Busy = false
	f.d.mu.Unlock()
	f.d.record("flush")
	return nil
}

func (f firewall) Busy() (bool, error) {
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	return f.d.Busy, nil
}

func (f firewall) Token() string {
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	return f.d.token
}

func (f firewall) Adopt(token string) {
	f.d.mu.Lock()
	f.d.token = token
	f.d.mu.Unlock()
	f.d.record("adopt %s", token)
}
