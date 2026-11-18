//go:build !darwin && !linux

package netinfo

import "net/netip"

// DefaultGateway is not implemented on this platform yet.
func DefaultGateway() (netip.Addr, bool) { return netip.Addr{}, false }
