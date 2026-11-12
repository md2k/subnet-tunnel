//go:build darwin

package darwin

import (
	"fmt"
	"net/netip"
	"os"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

// Utun creates utun interfaces.
type Utun struct{}

// Create makes a utun interface, sets its MTU and address and brings it up.
func (Utun) Create(mtu int, addr netip.Addr) (platform.TunDevice, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("utun address %s: IPv4 only so far", addr)
	}
	dev, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, fmt.Errorf("creating utun: %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	if err := run("/sbin/ifconfig", name, "inet", addr.String(), addr.String(), "up"); err != nil {
		_ = dev.Close()
		return nil, err
	}
	return &utunDevice{dev: dev, name: name}, nil
}

type utunDevice struct {
	dev  tun.Device
	name string
}

func (d *utunDevice) Name() string   { return d.name }
func (d *utunDevice) File() *os.File { return d.dev.File() }

// Release closes our descriptor only; macOS keeps the interface (and its
// routes) while subtun holds its copy.
func (d *utunDevice) Release() error { return d.dev.File().Close() }

func (d *utunDevice) Close() error { return d.dev.Close() }
