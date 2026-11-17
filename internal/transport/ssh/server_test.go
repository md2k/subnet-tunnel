package ssh

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testServer is an SSH server for the tests: it accepts the given keys,
// runs exec requests with the local sh, and forwards direct-tcpip channels
// (a jump host).
type testServer struct {
	addr    string
	port    int
	hostKey ssh.Signer
	mu      sync.Mutex
	logins  int
}

func newTestServer(t *testing.T, authorized ...ssh.PublicKey) *testServer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	hk, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{hostKey: hk}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		for _, a := range authorized {
			if bytes.Equal(a.Marshal(), k.Marshal()) {
				return nil, nil
			}
		}
		return nil, errors.New("not authorized")
	}}
	cfg.AddHostKey(hk)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s.addr = ln.Addr().String()
	s.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, cfg)
		}
	}()
	return s
}

func (s *testServer) serve(c net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		_ = c.Close()
		return
	}
	defer sc.Close()
	s.mu.Lock()
	s.logins++
	s.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, creqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go session(ch, creqs)
		case "direct-tcpip":
			var p struct {
				Host       string
				Port       uint32
				OriginHost string
				OriginPort uint32
			}
			if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
				_ = nc.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			to, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
			if err != nil {
				_ = nc.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			ch, creqs, err := nc.Accept()
			if err != nil {
				_ = to.Close()
				continue
			}
			go ssh.DiscardRequests(creqs)
			go func() { _, _ = io.Copy(to, ch); _ = to.Close() }()
			go func() { _, _ = io.Copy(ch, to); _ = ch.Close() }()
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "")
		}
	}
}

func (s *testServer) loginCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// session runs one exec request with sh -c, as sshd runs it with the login
// shell.
func session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		var p struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		cmd := exec.Command("sh", "-c", p.Command)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
		cmd.WaitDelay = time.Second
		code := 0
		if err := cmd.Run(); err != nil {
			code = 255
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			}
		}
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{uint32(code)}))
		return
	}
}
