package agentbin

import "testing"

func TestArchFromUname(t *testing.T) {
	for in, want := range map[string]string{"x86_64\n": "amd64", "aarch64": "arm64", "arm64": "arm64"} {
		if got, ok := ArchFromUname(in); !ok || got != want {
			t.Errorf("%q: got %q %v, want %q", in, got, ok, want)
		}
	}
	if _, ok := ArchFromUname("s390x"); ok {
		t.Error("s390x accepted")
	}
}

func TestRejectsNonELF(t *testing.T) {
	if _, err := newBinary("amd64", []byte("#!/bin/sh\necho hi\n")); err == nil {
		t.Fatal("shell script accepted as agent")
	}
	if _, err := newBinary("riscv64", nil); err == nil {
		t.Fatal("unsupported arch accepted")
	}
}

func TestRejectsWrongArch(t *testing.T) {
	bins, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bins {
		other := map[string]string{"amd64": "arm64", "arm64": "amd64"}[b.Arch]
		if _, err := newBinary(other, b.Data); err == nil {
			t.Errorf("%s agent accepted as %s", b.Arch, other)
		}
	}
}

func TestEmbedded(t *testing.T) {
	bins, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	// Plain `go test` runs without `make agents`; then nothing is embedded.
	for _, b := range bins {
		if b.SHA256 == "" || len(b.Data) == 0 {
			t.Errorf("%s: empty binary or checksum", b.Arch)
		}
	}
}
