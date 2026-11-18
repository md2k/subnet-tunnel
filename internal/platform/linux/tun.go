//go:build linux

package linux

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

const tunDev = "/dev/net/tun"

// Tun creates TUN interfaces (subtunN): plain IP packets, no packet
// information header, no offloads.
type Tun struct{}

// Create makes a TUN interface, sets its MTU and brings it up. It isn't
// persistent: the kernel removes it, with its routes, once no process holds
// it open.
//
// Unlike the macOS utun, it gets no address: routes into it don't need one,
// and connections through it use one of this machine's own addresses, to
// which the answers come back. A new address would make other software
// react: microk8s's apiserver-kicker adds it to the API server certificate
// and restarts the API server (and again when it goes), and mDNS responders
// may announce it. addr is checked but not assigned.
func (Tun) Create(mtu int, addr netip.Addr) (platform.TunDevice, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("TUN address %s: IPv4 only so far", addr)
	}
	fd, err := unix.Open(tunDev, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", tunDev, err)
	}
	ifr, err := unix.NewIfreq("subtun%d")
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("creating the TUN interface: %w", err)
	}
	d := &tunDevice{f: os.NewFile(uintptr(fd), tunDev), name: ifr.Name()}
	if !ifName.MatchString(d.name) {
		_ = d.Close()
		return nil, fmt.Errorf("the kernel named the TUN interface %q", d.name)
	}
	// No IPv6 on it (no link-local address, no router solicitations into
	// the tunnel): subtun captures IPv4 only so far. Best effort.
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+d.name+"/disable_ipv6", []byte("1"), 0o644)
	for _, args := range [][]string{
		{"link", "set", "dev", d.name, "mtu", strconv.Itoa(mtu)},
		{"link", "set", "dev", d.name, "up"},
	} {
		if err := run("ip", args...); err != nil {
			_ = d.Close()
			return nil, err
		}
	}
	return d, nil
}

type tunDevice struct {
	f    *os.File
	name string
}

func (d *tunDevice) Name() string   { return d.name }
func (d *tunDevice) File() *os.File { return d.f }

// Release closes our descriptor only; the interface lives on while subtun
// holds its copy.
func (d *tunDevice) Release() error { return d.f.Close() }

// Close closes our descriptor; with no other holder the interface goes.
func (d *tunDevice) Close() error { return d.f.Close() }
