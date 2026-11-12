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

	mu    sync.Mutex
	calls []string
	n     int
}

// Platform returns d as a platform.Drivers.
func (d *Drivers) Platform() platform.Drivers {
	return platform.Drivers{Tun: d, Routes: d}
}

// Calls returns the calls so far, e.g. "create utun0 9000 198.18.249.1",
// "add 10.0.0.0/8 utun0", "release utun0", "delete 10.0.0.0/8 utun0",
// "close utun0".
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
