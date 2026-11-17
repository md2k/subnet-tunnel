package relay

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
)

// Errors counts the errors a datagram relay carries on through (an ICMP error
// reported for one datagram, say), by direction and kind, for the log.
type Errors struct {
	mu     sync.Mutex
	counts map[string]int
	order  []string
	total  int
}

// Add counts err for dir ("read", "write"); it reports whether it's the first
// of its kind, to log that one.
func (e *Errors) Add(dir string, err error) bool {
	k := dir + ": " + errKind(err)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.counts == nil {
		e.counts = map[string]int{}
	}
	e.total++
	e.counts[k]++
	if e.counts[k] == 1 {
		e.order = append(e.order, k)
		return true
	}
	return false
}

// Total is the number of errors counted.
func (e *Errors) Total() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.total
}

// String lists the counts in the order first seen, e.g.
// "read: no route to host (2), write: message too long (1)"; "" for none.
func (e *Errors) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	parts := make([]string, len(e.order))
	for i, k := range e.order {
		parts[i] = fmt.Sprintf("%s (%d)", k, e.counts[k])
	}
	return strings.Join(parts, ", ")
}

// errKind is the error without the operation and addresses around it.
func errKind(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	for {
		var oe *net.OpError
		var se *os.SyscallError
		switch {
		case errors.As(err, &oe) && oe.Err != nil:
			err = oe.Err
		case errors.As(err, &se) && se.Err != nil:
			err = se.Err
		default:
			return err.Error()
		}
	}
}
