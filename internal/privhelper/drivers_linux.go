package privhelper

import (
	"log/slog"

	"github.com/md2k/subnet-tunnel/internal/platform"
	"github.com/md2k/subnet-tunnel/internal/platform/linux"
)

// osDrivers are the Linux drivers: TUN, routes in subtun's own table with
// `ip`, nftables, systemd-resolved's cache.
func osDrivers(*slog.Logger) platform.Drivers {
	return platform.Drivers{
		Tun:      linux.Tun{},
		Routes:   linux.Route{},
		Firewall: linux.Firewall{},
		DNSCache: linux.DNSCache{},
	}
}
