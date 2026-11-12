//go:build !darwin

package privhelper

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

var errUnsupported = errors.New("utun capture is only implemented on macOS so far; use --socks")

// Client is subtun's side of a running helper.
type Client struct{}

// Start is not implemented on this platform yet.
func Start(context.Context, io.Writer, *slog.Logger) (*Client, error) { return nil, errUnsupported }

// CreateTun is not implemented on this platform yet.
func (*Client) CreateTun(int, netip.Addr) (string, *os.File, error) { return "", nil, errUnsupported }

// AddRoute is not implemented on this platform yet.
func (*Client) AddRoute(netip.Prefix) error { return errUnsupported }

// ApplyFirewall is not implemented on this platform yet.
func (*Client) ApplyFirewall(platform.Rules, *platform.Rules) error { return errUnsupported }

// End is not implemented on this platform yet.
func (*Client) End(bool) error { return errUnsupported }

// Adopt is not implemented on this platform yet.
func (*Client) Adopt() (AdoptResult, error) { return AdoptResult{}, errUnsupported }

// AdoptResult says what Adopt found.
type AdoptResult struct {
	Kept, Running bool
	Message       string
}

// Cleanup is not implemented on this platform yet.
func (*Client) Cleanup() (string, error) { return "", errUnsupported }

// DoneSession is not implemented on this platform yet.
func (*Client) DoneSession() error { return errUnsupported }

// Exited is not implemented on this platform yet.
func (*Client) Exited() <-chan struct{} { return nil }

// Done is not implemented on this platform yet.
func (*Client) Done() error { return errUnsupported }

// Close is not implemented on this platform yet.
func (*Client) Close() error { return nil }

// MarkLeftovers is not implemented on this platform yet.
func MarkLeftovers() error { return nil }

// ClearLeftovers is not implemented on this platform yet.
func ClearLeftovers() {}

// LeftoversMarked is not implemented on this platform yet.
func LeftoversMarked() bool { return false }

// Serve is not implemented on this platform yet.
func Serve(context.Context, string, io.Reader, *slog.Logger) error { return errUnsupported }
