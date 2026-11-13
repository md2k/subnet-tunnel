package cli

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/routes"
	"github.com/md2k/subnet-tunnel/internal/transport"
)

// Dry runs don't depend on the machine's networks: one LAN, 192.168.77.0/24
// on en0, with its gateway.
func TestMain(m *testing.M) {
	// Never the user's own config file.
	os.Setenv("SUBTUN_CONFIG", "testdata/no-such-config.yaml")
	localNetworks = func() []routes.Local {
		return []routes.Local{{Iface: "en0", Network: netip.MustParsePrefix("192.168.77.0/24")}}
	}
	defaultGateway = func() (netip.Addr, bool) { return netip.MustParseAddr("192.168.77.1"), true }
	systemSearch = func() ([]string, error) { return []string{"lan"}, nil }
	// Endpoints: IP literals as they are, one name, nothing else (no DNS).
	lookupEndpoint = func(_ context.Context, raw string) ([]netip.Addr, error) {
		host := transport.HostName(raw)
		if host == "api.named.example.test" {
			return []netip.Addr{netip.MustParseAddr("172.24.9.9")}, nil
		}
		if a, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{a}, nil
		}
		if host == "" {
			return nil, nil
		}
		return nil, errors.New("no such host (test)")
	}
	os.Exit(m.Run())
}
