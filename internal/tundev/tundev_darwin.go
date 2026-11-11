// Package tundev adapts the platform TUN interface to netstack.Device.
package tundev

import (
	"fmt"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

// utunHeader is the address-family word in front of every utun packet.
const utunHeader = 4

// Device is a utun interface opened from a file descriptor the root helper
// passed over. Read and Write are each used by one goroutine at a time.
type Device struct {
	nt    tun.Device
	name  string
	mtu   int
	rbufs [][]byte
	sizes []int
	wbufs [][]byte
}

// FromFile wraps an already configured utun. The MTU was set by the helper
// (mtu 0 here skips the ioctl, which would need root).
func FromFile(f *os.File) (*Device, error) {
	nt, err := tun.CreateTUNFromFile(f, 0)
	if err != nil {
		return nil, fmt.Errorf("opening utun: %w", err)
	}
	name, err := nt.Name()
	if err != nil {
		_ = nt.Close()
		return nil, err
	}
	mtu, err := nt.MTU()
	if err != nil {
		_ = nt.Close()
		return nil, err
	}
	return &Device{nt: nt, name: name, mtu: mtu, rbufs: make([][]byte, 1), sizes: make([]int, 1), wbufs: make([][]byte, 1)}, nil
}

// Name is the interface name (utunN).
func (d *Device) Name() string { return d.name }

// Headroom implements netstack.Device.
func (d *Device) Headroom() int { return utunHeader }

// MTU implements netstack.Device.
func (d *Device) MTU() int { return d.mtu }

// Read implements netstack.Device.
func (d *Device) Read(buf []byte) (int, error) {
	d.rbufs[0] = buf
	if _, err := d.nt.Read(d.rbufs, d.sizes, utunHeader); err != nil {
		return 0, err
	}
	return d.sizes[0], nil
}

// Write implements netstack.Device.
func (d *Device) Write(buf []byte) error {
	d.wbufs[0] = buf
	_, err := d.nt.Write(d.wbufs, utunHeader)
	return err
}

// Close closes the interface; macOS removes it, and every route on it, once
// no process holds it open.
func (d *Device) Close() error { return d.nt.Close() }
