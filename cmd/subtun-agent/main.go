// Command subtun-agent is the remote end of subtun. subtun uploads it into the
// target and starts it with the tunnel carrier on stdin/stdout. It is not
// meant to be run by hand.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/md2k/subnet-tunnel/internal/agent"
	"github.com/md2k/subnet-tunnel/internal/version"
)

func main() {
	verbose := flag.Bool("v", false, "debug logging")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	// No timestamps: subtun relays these lines into its own log.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	err := agent.Serve(ctx, stdio{}, agent.Config{
		Version: version.Version,
		SHA256:  selfSHA256(),
		Logger:  log,
	})
	if err != nil {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}

// stdio is the carrier: subtun's exec (or SSH) session.
type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error {
	_ = os.Stdin.Close()
	return os.Stdout.Close()
}

// selfSHA256 lets subtun verify that the binary running is the one it
// uploaded. Empty if the executable can't be read.
func selfSHA256() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
