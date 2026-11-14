//go:build unix

package cli

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// While captured, what is written to fd 2 goes to the log, and the
// terminal's own standard error is still there to write to; restore puts
// fd 2 back.
func TestCaptureFd2(t *testing.T) {
	var mu sync.Mutex
	var logged bytes.Buffer
	log := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logged.Write(p)
	}), nil))
	term, restore, err := captureFd2(log)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stderr, "from a login plugin")
	if term == nil || term.Fd() == 2 {
		t.Errorf("the terminal's standard error: %v", term)
	}
	restore()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		s := logged.String()
		mu.Unlock()
		if strings.Contains(s, `msg="stderr: from a login plugin"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not logged: %q", s)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
