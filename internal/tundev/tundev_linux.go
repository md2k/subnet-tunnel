// Package tundev adapts the platform TUN interface to netstack.Device.
package tundev

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Device is a Linux TUN interface opened from a file descriptor the root
// helper passed over: plain IP packets (no packet information header), one
// per read or write.
type Device struct {
	f    *os.File
	name string
	mtu  int
}

// FromFile takes over the descriptor. It asks the kernel for the
// interface's name, switches the descriptor to non-blocking so Go's poller
// serves reads and writes (and Close interrupts a read), and reads the MTU
// the helper set.
func FromFile(f *os.File) (*Device, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var name string
	nfd := -1
	var cerr error
	if err := rc.Control(func(fd uintptr) {
		ifr, err := unix.NewIfreq("")
		if err != nil {
			cerr = err
			return
		}
		if err := unix.IoctlIfreq(int(fd), unix.TUNGETIFF, ifr); err != nil {
			cerr = fmt.Errorf("not a TUN interface: %w", err)
			return
		}
		name = ifr.Name()
		if nfd, err = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0); err != nil {
			cerr = err
			return
		}
		if err := unix.SetNonblock(nfd, true); err != nil {
			_ = unix.Close(nfd)
			nfd, cerr = -1, err
		}
	}); err != nil {
		return nil, err
	}
	if cerr != nil {
		return nil, cerr
	}
	nf := os.NewFile(uintptr(nfd), "/dev/net/tun")
	_ = f.Close()
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		_ = nf.Close()
		return nil, err
	}
	return &Device{f: nf, name: name, mtu: ifc.MTU}, nil
}

// Name is the interface name (subtunN).
func (d *Device) Name() string { return d.name }

// Headroom implements netstack.Device: no header in front of packets.
func (d *Device) Headroom() int { return 0 }

// MTU implements netstack.Device.
func (d *Device) MTU() int { return d.mtu }

// Read implements netstack.Device.
func (d *Device) Read(buf []byte) (int, error) { return d.f.Read(buf) }

// Write implements netstack.Device.
func (d *Device) Write(buf []byte) error {
	_, err := d.f.Write(buf)
	return err
}

// Close closes the interface; the kernel removes it, and every route on it,
// once no process holds it open.
func (d *Device) Close() error { return d.f.Close() }
