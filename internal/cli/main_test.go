package cli

import (
	"net/netip"
	"os"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/routes"
)

// Dry runs don't depend on the machine's networks: one LAN, 192.168.77.0/24
// on en0, with its gateway.
func TestMain(m *testing.M) {
	localNetworks = func() []routes.Local {
		return []routes.Local{{Iface: "en0", Network: netip.MustParsePrefix("192.168.77.0/24")}}
	}
	defaultGateway = func() (netip.Addr, bool) { return netip.MustParseAddr("192.168.77.1"), true }
	systemSearch = func() ([]string, error) { return []string{"lan"}, nil }
	os.Exit(m.Run())
}
