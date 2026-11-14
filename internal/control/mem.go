package control

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// InMemory answers the API inside this process until ctx ends: the client
// it returns is the one a terminal UI running in subtun itself talks
// through. Same API and client as the socket, without a socket.
func (s *Server) InMemory(ctx context.Context) *Client {
	ln := &pipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close() // ends the log streams too
		_ = ln.Close()
	}()
	go func() { _ = srv.Serve(ln) }()
	tr := &http.Transport{DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) { return ln.dial(dctx) }}
	return &Client{hc: &http.Client{Transport: tr}}
}

// pipeListener hands out the server's ends of in-memory connections.
type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *pipeListener) dial(ctx context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.done:
	case <-ctx.Done():
	}
	_ = client.Close()
	_ = server.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, net.ErrClosed
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "in-memory" }
