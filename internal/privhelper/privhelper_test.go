package privhelper

import (
	"strings"
	"testing"
)

func TestParseCIDR(t *testing.T) {
	ok := map[string]string{
		"10.244.0.0/16": "10.244.0.0/16",
		"10.96.0.10":    "10.96.0.10/32",
		"172.20.0.0/24": "172.20.0.0/24",
	}
	for in, want := range ok {
		p, err := ParseCIDR(in)
		if err != nil || p.String() != want {
			t.Errorf("%q: got %v, %v; want %s", in, p, err, want)
		}
	}
	bad := map[string]string{
		"10.244.1.0/16":  "did you mean 10.244.0.0/16",
		"0.0.0.0/0":      "default route",
		"127.0.0.0/8":    "loopback",
		"224.0.0.0/4":    "multicast",
		"fd00::/8":       "IPv4",
		"web.svc":        "not an IP",
		"10.0.0.0/33":    "not an IP",
		"10.0.0.0/8; rm": "not an IP",
	}
	for in, want := range bad {
		if _, err := ParseCIDR(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want error containing %q", in, err, want)
		}
	}
}

func TestValidateTunAddrAndMTU(t *testing.T) {
	if _, err := ValidateTunAddr("198.18.249.1"); err != nil {
		t.Error(err)
	}
	for _, a := range []string{"127.0.0.1", "0.0.0.0", "169.254.1.1", "fd00::1", "224.0.0.1", "nope"} {
		if _, err := ValidateTunAddr(a); err == nil {
			t.Errorf("%s accepted as utun address", a)
		}
	}
	if ValidateMTU(9000) != nil || ValidateMTU(100) == nil || ValidateMTU(70000) == nil {
		t.Error("MTU bounds")
	}
}
