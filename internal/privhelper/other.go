//go:build !darwin

package privhelper

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
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

// Done is not implemented on this platform yet.
func (*Client) Done() error { return errUnsupported }

// Close is not implemented on this platform yet.
func (*Client) Close() error { return nil }

// Serve is not implemented on this platform yet.
func Serve(context.Context, string, io.Reader, *slog.Logger) error { return errUnsupported }
