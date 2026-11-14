package cli

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/logring"
	"github.com/md2k/subnet-tunnel/internal/logx"
	"github.com/md2k/subnet-tunnel/internal/xdg"
)

// logFlags are the log settings' flags (global for the run, as the
// config's top-level log key).
var logFlags = []string{"log-file", "log-dir", "log-format", "log-level", "log-mask", "log-max-size", "log-max-age", "log-max-total"}

func registerLogFlags(cmd *cobra.Command, l *config.Log) {
	f := cmd.Flags()
	f.Var((*wordFlag)(&l.File), "log-file", "write a log file: on (default) or off")
	f.StringVar(&l.Dir, "log-dir", "", "directory for log files (default ~/.local/state/subtun/logs)")
	f.StringVar(&l.Format, "log-format", "", "log file format: json (default) or text")
	f.StringVar(&l.Level, "log-level", "", "log level, and per component: info (default), or e.g. info,dns=debug (components: tunnel, dns, conn, capture, helper, control, socks, transport)")
	f.StringSliceVar(&l.Mask, "log-mask", nil, "mask in logs: dns (names), destinations (addresses), or both")
	f.StringVar(&l.MaxSize, "log-max-size", "", "start a new log file part at this size (default 20MB)")
	f.StringVar(&l.MaxAge, "log-max-age", "", "remove log files older than this (default 3d)")
	f.StringVar(&l.MaxTotal, "log-max-total", "", "remove the oldest log files while all take more than this (default 500MB)")
}

// wordFlag is a flag holding a config.Word.
type wordFlag config.Word

func (w *wordFlag) String() string { return string(*w) }
func (w *wordFlag) Set(s string) error {
	switch s {
	case "true":
		s = "on"
	case "false":
		s = "off"
	}
	*w = wordFlag(s)
	return nil
}
func (w *wordFlag) Type() string { return "string" }

// mergeLog fills the log settings flags didn't give from the config file's
// log key; the result is checked.
func mergeLog(flags *pflag.FlagSet, l *config.Log, f config.Log) error {
	set := flags.Changed
	if !set("log-file") {
		l.File = f.File
	}
	if !set("log-dir") {
		l.Dir = f.Dir
	}
	if !set("log-format") {
		l.Format = f.Format
	}
	if !set("log-level") {
		l.Level, l.Levels = f.Level, f.Levels
	}
	if !set("log-mask") {
		l.Mask = f.Mask
	}
	if !set("log-max-size") {
		l.MaxSize = f.MaxSize
	}
	if !set("log-max-age") {
		l.MaxAge = f.MaxAge
	}
	if !set("log-max-total") {
		l.MaxTotal = f.MaxTotal
	}
	return l.Validate()
}

// runLog is a run's logging: the terminal, the ring buffer behind subtun
// logs, and the log file.
type runLog struct {
	log    *slog.Logger
	ring   *logring.Ring
	file   *logx.File   // nil: no file
	levels *logx.Levels // changed while running by subtun log level
}

func (r *runLog) close() {
	if r.file != nil {
		_ = r.file.Close()
	}
}

// newRunLog sets up a run's logging. With verbose (-v) everything logs at
// debug. domains reads the configured DNS domains (masked names keep
// theirs). A log file that can't be opened costs only the file: the
// returned warning says so.
func newRunLog(verbose bool, lc config.Log, domains func() []string, stderr io.Writer) (*runLog, string) {
	spec, _ := logx.ParseSpec(lc.Level) // checked with the settings
	for c, l := range lc.Levels {
		_ = spec.Set(c, l)
	}
	if verbose {
		spec = logx.Spec{Default: slog.LevelDebug}
	}
	mask := logx.NewMasker(slices.Contains(lc.Mask, "dns"), slices.Contains(lc.Mask, "destinations"), domains)
	levels := logx.NewLevels(spec)
	// The terminal and the ring: text, short times, no component.
	termOpts := &slog.HandlerOptions{Level: levels.Min(), ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 {
			switch a.Key {
			case slog.TimeKey:
				return slog.String(slog.TimeKey, a.Value.Time().Format("15:04:05.000"))
			case logx.ComponentKey:
				return slog.Attr{}
			}
		}
		return mask.Replace(groups, a)
	}}
	r := &runLog{ring: logring.New(0, 0), levels: levels}
	handlers := []slog.Handler{slog.NewTextHandler(stderr, termOpts), r.ring.Handler(termOpts)}
	var warn string
	if lc.File != "off" {
		if f, err := openLogFile(lc); err != nil {
			warn = fmt.Sprintf("no log file: %v", err)
		} else {
			r.file = f
			fileOpts := &slog.HandlerOptions{Level: levels.Min(), ReplaceAttr: mask.Replace}
			if lc.Format == "text" {
				handlers = append(handlers, slog.NewTextHandler(f, fileOpts))
			} else {
				handlers = append(handlers, slog.NewJSONHandler(f, fileOpts))
			}
		}
	}
	r.log = slog.New(logx.FilterLevels(logring.Tee(handlers...), levels))
	return r, warn
}

func openLogFile(lc config.Log) (*logx.File, error) {
	opts := logx.FileOptions{Dir: lc.Dir, Ext: "json"}
	if lc.Format == "text" {
		opts.Ext = "log"
	}
	if opts.Dir == "" { // the default directory is the user's only
		d, err := xdg.LogDir()
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, err
		}
		opts.Dir = d
	} else {
		opts.Dir = config.ExpandHome(opts.Dir)
	}
	opts.MaxSize, _ = logx.ParseSize(orDefault(lc.MaxSize, "20MB"))
	opts.MaxTotal, _ = logx.ParseSize(orDefault(lc.MaxTotal, "500MB"))
	opts.MaxAge, _ = logx.ParseAge(orDefault(lc.MaxAge, "3d"))
	return logx.OpenFile(opts, time.Now())
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
