package privhelper

import (
	"log/slog"

	"github.com/md2k/subnet-tunnel/internal/platform"
	"github.com/md2k/subnet-tunnel/internal/platform/darwin"
)

// osDrivers are the macOS drivers: utun, /sbin/route, pf, mDNSResponder.
func osDrivers(log *slog.Logger) platform.Drivers {
	return platform.Drivers{
		Tun:      darwin.Utun{},
		Routes:   darwin.Route{},
		Firewall: &darwin.PF{Log: log},
		DNSCache: darwin.DNSCache{},
	}
}
