package logx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// logName is a subtun log file's name: subtun-<date>-<time>-<pid>[-<part>].
var logName = regexp.MustCompile(`^subtun-\d{8}-\d{6}-(\d+)(?:-\d+)?\.(?:json|log)$`)

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
	// A new name every time: O_EXCL also refuses to follow a symlink
	// planted under it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
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
	if rotated {
		l.pruneLocked(time.Now())
	}
	l.mu.Unlock()
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

// prune removes old log files: subtun's only (by their exact names), never
// the one in use, nor another running subtun's.
func (l *File) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
}

func (l *File) pruneLocked(now time.Time) {
	current := l.path
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
		m := logName.FindStringSubmatch(name)
		if e.IsDir() || m == nil {
			continue
		}
		if pid, _ := strconv.Atoi(m[1]); pid != os.Getpid() && running(pid) {
			continue // another subtun is still writing it
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
	total := l.size
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

// running reports whether a process with this pid exists.
func running(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, os.ErrPermission)
}

// ParseSize reads a size: 20MB, 500KB, 1GB, or plain bytes.
func ParseSize(s string) (int64, error) {
	v := strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(v, u.suffix) {
			v, mult = strings.TrimSpace(strings.TrimSuffix(v, u.suffix)), u.mult
			break
		}
	}
	var n int64
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n <= 0 || fmt.Sprint(n) != v {
		return 0, fmt.Errorf("size %q: a positive number with KB, MB or GB", s)
	}
	return n * mult, nil
}

// ParseAge reads a duration, with days too: 3d, 12h, 90m.
func ParseAge(s string) (time.Duration, error) {
	v := strings.TrimSpace(s)
	if d, ok := strings.CutSuffix(v, "d"); ok {
		var n int
		if _, err := fmt.Sscanf(d, "%d", &n); err == nil && n > 0 && fmt.Sprint(n) == d {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	} else if dur, err := time.ParseDuration(v); err == nil && dur > 0 {
		return dur, nil
	}
	return 0, fmt.Errorf("age %q: a positive duration such as 3d, 12h or 90m", s)
}
