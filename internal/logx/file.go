package logx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// File defaults (log.maxSize, log.maxAge, log.maxTotal).
const (
	DefaultMaxSize  = 20 << 20
	DefaultMaxAge   = 72 * time.Hour
	DefaultMaxTotal = 500 << 20
)

// pruneEvery is how often old files are looked for while running.
const pruneEvery = time.Hour

// FileOptions configures a log file.
type FileOptions struct {
	Dir      string        // created 0700
	Ext      string        // "json" or "log"
	MaxSize  int64         // a file this large is followed by the next part; 0: DefaultMaxSize
	MaxAge   time.Duration // files older than this are removed; 0: DefaultMaxAge
	MaxTotal int64         // the oldest files go while all are larger than this; 0: DefaultMaxTotal
}

// File is one run's log: subtun-<start>-<pid>.<ext>, then -2, -3 as it
// grows past MaxSize. Opening it, each new part and every hour remove
// subtun's log files older than MaxAge, then the oldest while all of them
// take more than MaxTotal; never the file in use. Each Write is one log
// record (slog handlers write a record at once), so parts split between
// records.
type File struct {
	opts  FileOptions
	base  string // subtun-<start>-<pid>
	mu    sync.Mutex
	f     *os.File
	path  string
	size  int64
	part  int
	stop  chan struct{}
	close sync.Once
}

// OpenFile starts a run's log file.
func OpenFile(opts FileOptions, now time.Time) (*File, error) {
	if opts.MaxSize <= 0 {
		opts.MaxSize = DefaultMaxSize
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = DefaultMaxAge
	}
	if opts.MaxTotal <= 0 {
		opts.MaxTotal = DefaultMaxTotal
	}
	if opts.Ext == "" {
		opts.Ext = "json"
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	l := &File{opts: opts, base: fmt.Sprintf("subtun-%s-%d", now.Format("20060102-150405"), os.Getpid()), stop: make(chan struct{})}
	if err := l.openPart(1); err != nil {
		return nil, err
	}
	l.prune(now)
	go l.pruneLoop()
	return l, nil
}

// Path is the file being written.
func (l *File) Path() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.path
}

func (l *File) openPart(n int) error {
	name := l.base
	if n > 1 {
		name = fmt.Sprintf("%s-%d", l.base, n)
	}
	path := filepath.Join(l.opts.Dir, name+"."+l.opts.Ext)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if l.f != nil {
		_ = l.f.Close()
	}
	l.f, l.path, l.size, l.part = f, path, 0, n
	return nil
}

// Write appends a record, starting the next part first if this one is full.
func (l *File) Write(p []byte) (int, error) {
	l.mu.Lock()
	if l.f == nil {
		l.mu.Unlock()
		return 0, errors.New("log file closed")
	}
	rotated := false
	if l.size > 0 && l.size+int64(len(p)) > l.opts.MaxSize {
		if err := l.openPart(l.part + 1); err != nil {
			l.mu.Unlock()
			return 0, err
		}
		rotated = true
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	l.mu.Unlock()
	if rotated {
		l.prune(time.Now())
	}
	return n, err
}

// Close stops writing.
func (l *File) Close() error {
	var err error
	l.close.Do(func() {
		close(l.stop)
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.f != nil {
			err = l.f.Close()
			l.f = nil
		}
	})
	return err
}

func (l *File) pruneLoop() {
	t := time.NewTicker(pruneEvery)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case now := <-t.C:
			l.prune(now)
		}
	}
}

// prune removes old log files, never the one in use.
func (l *File) prune(now time.Time) {
	current := l.Path()
	entries, err := os.ReadDir(l.opts.Dir)
	if err != nil {
		return
	}
	type logFile struct {
		path string
		mod  time.Time
		size int64
	}
	var files []logFile
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "subtun-") || !(strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".log")) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(l.opts.Dir, name)
		if path == current {
			continue
		}
		if now.Sub(info.ModTime()) > l.opts.MaxAge {
			_ = os.Remove(path)
			continue
		}
		files = append(files, logFile{path, info.ModTime(), info.Size()})
	}
	total := int64(0)
	if info, err := os.Stat(current); err == nil {
		total = info.Size()
	}
	for _, f := range files {
		total += f.size
	}
	slices.SortFunc(files, func(a, b logFile) int { return a.mod.Compare(b.mod) })
	for _, f := range files {
		if total <= l.opts.MaxTotal {
			break
		}
		if os.Remove(f.path) == nil {
			total -= f.size
		}
	}
}
