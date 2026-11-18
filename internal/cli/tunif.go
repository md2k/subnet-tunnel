package cli

import (
	"fmt"
	"net/netip"
	"runtime"
)

// tunAddrAssigned: the macOS utun carries subtun's address (point-to-point
// to itself); the Linux TUN has none (internal/platform/linux).
var tunAddrAssigned = runtime.GOOS != "linux"

// tunIfaceText describes the tunnel interface for the dry run.
func tunIfaceText(addr netip.Addr, mtu int) string {
	if tunAddrAssigned {
		return fmt.Sprintf("tunnel interface %s, MTU %d", addr, mtu)
	}
	return fmt.Sprintf("tunnel interface (no address), MTU %d", mtu)
}

// shownTunAddr is the interface's address for the status ("" if it has none).
func shownTunAddr(addr netip.Addr) string {
	if !tunAddrAssigned {
		return ""
	}
	return addr.String()
}
