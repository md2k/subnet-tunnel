//go:build !darwin && !linux

// Package tundev adapts the platform TUN interface to netstack.Device.
package tundev

import (
	"errors"
	"os"
)

// Device is not implemented on this platform yet.
type Device struct{}

// FromFile is not implemented on this platform yet.
func FromFile(*os.File) (*Device, error) {
	return nil, errors.New("TUN capture is only implemented on macOS so far")
}

// Name is not implemented on this platform yet.
func (*Device) Name() string { return "" }

// Headroom is not implemented on this platform yet.
func (*Device) Headroom() int { return 0 }

// MTU is not implemented on this platform yet.
func (*Device) MTU() int { return 0 }

// Read is not implemented on this platform yet.
func (*Device) Read([]byte) (int, error) { return 0, errors.ErrUnsupported }

// Write is not implemented on this platform yet.
func (*Device) Write([]byte) error { return errors.ErrUnsupported }

// Close is not implemented on this platform yet.
func (*Device) Close() error { return nil }
