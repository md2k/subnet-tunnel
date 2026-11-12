// Package platform defines what subtun needs from the operating system, as
// small interfaces implemented once per OS ("drivers").
//
// Drivers describe intent, not syntax: callers say "route this prefix into
// that interface", and each driver turns that into its OS's mechanism. App
// code never contains route, pf or nftables syntax. Drivers need root, so
// they run inside the root helper (internal/privhelper); the helper accepts
// only validated commands and calls the drivers with them.
//
// Implementations: internal/platform/darwin (macOS). internal/platform/fake
// records calls for tests.
package platform

import (
	"net/netip"
	"os"
)

// Drivers is the set of drivers the helper works with.
type Drivers struct {
	Tun      Tun
	Routes   Routes
	Firewall Firewall
}

// Tun creates the capture interface (macOS utun; later Linux TUN, Windows
// wintun).
type Tun interface {
	// Create makes an interface with the given MTU and its own address
	// (point-to-point to itself) and brings it up. Arguments are validated by
	// the caller.
	Create(mtu int, addr netip.Addr) (TunDevice, error)
}

// TunDevice is an interface created by a Tun driver. The helper hands its
// descriptor to subtun, then releases its own copy.
type TunDevice interface {
	// Name is the OS interface name (utunN).
	Name() string
	// File is the descriptor passed to subtun over the helper socket.
	File() *os.File
	// Release closes the helper's copy after the descriptor was handed over.
	// The interface lives on as long as subtun holds its copy.
	Release() error
	// Close destroys the interface (used when setup is abandoned).
	Close() error
}

// Routes adds and removes routes that send a prefix into an interface.
type Routes interface {
	Add(p netip.Prefix, iface string) error
	Delete(p netip.Prefix, iface string) error
}

// Firewall manages subtun's own firewall rules (macOS: a pf anchor), never
// anyone else's.
type Firewall interface {
	// Apply replaces subtun's rules with r in one step. The first Apply
	// enables the firewall if it is off.
	Apply(r Rules) error
	// Flush removes subtun's rules and undoes the enabling done by Apply.
	Flush() error
}

// Rules is what subtun needs from the firewall, described as intent.
type Rules struct {
	DNS *DNSRedirect `json:"dns,omitempty"`
}

// DNSRedirect captures DNS (UDP and TCP port 53) sent to Servers and
// delivers it to subtun's DNS listener on 127.0.0.1:ListenPort. Packets
// sent from BypassPort (subtun's own fallback queries) pass untouched, so
// they can't loop back.
type DNSRedirect struct {
	Servers    []netip.Addr `json:"servers"`
	ListenPort uint16       `json:"listen_port"`
	BypassPort uint16       `json:"bypass_port"`
}
