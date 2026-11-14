package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// errMaxDuration ends the run's context when --max-duration runs out.
var errMaxDuration = errors.New("--max-duration reached")

var (
	// stopGrace is how long stopping may take after --max-duration before
	// subtun exits anyway.
	stopGrace = 20 * time.Second
	// hardExit ends the process when stopping hangs; replaced in tests.
	hardExit = os.Exit
	// beforeHardExit, when set, runs before hardExit: the terminal UI gives
	// the terminal back (raw mode, the alternate screen) and prints why.
	beforeHardExit atomic.Pointer[func()]
)

// withMaxDuration ends ctx after d, which stops subtun the way Ctrl-C does:
// routes and firewall rules go (a kill switch in lockdown keeps its blocks).
// It's a safety net for tests that may cut the network, such as a full
// tunnel or the kill switch. If stopping hangs, the process exits stopGrace
// later: macOS then removes the utun and its routes, and the root helper,
// seeing subtun gone, removes its rules except a kill switch's blocks (as
// after a crash). The returned done must be called when the run returns.
func withMaxDuration(ctx context.Context, d time.Duration, log *slog.Logger) (context.Context, func()) {
	if d <= 0 {
		return ctx, func() {}
	}
	ctx, cancel := context.WithTimeoutCause(ctx, d, errMaxDuration)
	watchdog := time.AfterFunc(d+stopGrace, func() {
		log.Error("still stopping after --max-duration; exiting now", "grace", stopGrace)
		if f := beforeHardExit.Load(); f != nil {
			(*f)()
		}
		hardExit(3)
	})
	log.Info("subtun stops by itself after --max-duration", "max_duration", d)
	return ctx, func() {
		watchdog.Stop()
		cancel()
	}
}

// maxDurationReached reports whether ctx ended because --max-duration ran
// out.
func maxDurationReached(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), errMaxDuration)
}

// startErr replaces err with a clear message when --max-duration ran out
// before subtun was up (connecting, the sudo prompt).
func startErr(ctx context.Context, err error) error {
	if maxDurationReached(ctx) {
		return fmt.Errorf("%w before the tunnel was up", errMaxDuration)
	}
	return err
}

// logShutdown says why subtun is stopping deliberately.
func logShutdown(ctx context.Context, log *slog.Logger) {
	if maxDurationReached(ctx) {
		log.Info("--max-duration reached, shutting down")
		return
	}
	log.Info("shutting down")
}
