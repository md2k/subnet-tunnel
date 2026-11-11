// Package relay copies bytes between two connections in both directions.
package relay

import (
	"io"
	"sync"
)

type closeWriter interface{ CloseWrite() error }

// Pipe copies a→b and b→a until both directions are done, then closes both.
//
// When one side reaches EOF, the other side's write half is closed (if it
// supports CloseWrite) so the peer sees EOF while the reverse direction keeps
// flowing; request/response protocols that shut down their write side rely on
// this. If a copy fails, or the destination can't half-close, both
// connections are closed so the other direction stops too.
func Pipe(a, b io.ReadWriteCloser) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); aToB = half(b, a) }()
	go func() { defer wg.Done(); bToA = half(a, b) }()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
	return aToB, bToA
}

func half(dst, src io.ReadWriteCloser) int64 {
	n, err := io.Copy(dst, src)
	if err == nil {
		if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
			return n
		}
	}
	_ = dst.Close()
	_ = src.Close()
	return n
}
