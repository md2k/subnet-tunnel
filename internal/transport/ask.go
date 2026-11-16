package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

// Questions a connect may ask on the terminal while subtun runs: an
// unknown SSH host key, a key's passphrase. up --tui lends the terminal for
// them, as it does for sudo.

type lendKey struct{}

// WithLend gives the connects under ctx a way to borrow the terminal: lend
// runs f while the terminal is theirs.
func WithLend(ctx context.Context, lend func(f func())) context.Context {
	if lend == nil {
		return ctx
	}
	return context.WithValue(ctx, lendKey{}, lend)
}

// ErrNoTerminal is Ask's error when there is no terminal to ask on.
var ErrNoTerminal = errors.New("no terminal to ask on")

var askMu sync.Mutex // one question at a time, whichever profile asks

// Ask asks on the controlling terminal and returns the answer's line;
// secret doesn't echo it.
func Ask(ctx context.Context, question string, secret bool) (string, error) {
	askMu.Lock()
	defer askMu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var answer string
	var err error
	ask := func() { answer, err = askTTY(ctx, question, secret) }
	if lend, ok := ctx.Value(lendKey{}).(func(func())); ok {
		lend(ask)
	} else {
		ask()
	}
	return answer, err
}

func askTTY(ctx context.Context, question string, secret bool) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", ErrNoTerminal
	}
	defer tty.Close()
	stop := context.AfterFunc(ctx, func() { _ = tty.Close() }) // best effort: a stop while asking
	defer stop()
	if _, err := fmt.Fprint(tty, question); err != nil {
		return "", ErrNoTerminal
	}
	if secret {
		b, err := term.ReadPassword(int(tty.Fd()))
		_, _ = fmt.Fprintln(tty)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return string(b), err
	}
	line, err := bufio.NewReader(tty).ReadString('\n')
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
