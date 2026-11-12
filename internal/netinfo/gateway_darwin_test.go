package netinfo

import "testing"

func TestParseRouteGet(t *testing.T) {
	viaRouter := `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	if a, ok := parseRouteGet(viaRouter); !ok || a.String() != "192.168.1.1" {
		t.Fatalf("got %v %v", a, ok)
	}
	viaInterface := `   route to: default
destination: default
  interface: utun4
      flags: <UP,DONE,STATIC>
`
	if _, ok := parseRouteGet(viaInterface); ok {
		t.Fatal("interface route reported as a gateway address")
	}
	if _, ok := parseRouteGet("    gateway: utun4\n"); ok {
		t.Fatal("interface name parsed as an address")
	}
}
