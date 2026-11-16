package ssh

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/md2k/subnet-tunnel/internal/transport"
)

var quiet = slog.New(slog.DiscardHandler)

// ssh -G's output: values as OpenSSH prints them, ~ and % tokens expanded
// here.
func TestParseConfig(t *testing.T) {
	home, _ := os.UserHomeDir()
	c, err := parseConfig("db", `user bob
hostname db.internal.example.com
port 2222
identityfile ~/.ssh/id_ed25519
identityfile ~/.ssh/%h-%r
certificatefile ~/.ssh/ca-cert.pub
proxyjump alice@bastion:2200,jump2
userknownhostsfile ~/.ssh/known_hosts /etc/extra_hosts
globalknownhostsfile /etc/ssh/ssh_known_hosts
stricthostkeychecking false
hashknownhosts yes
identitiesonly yes
identityagent ~/.agent.sock
connecttimeout 7
serveraliveinterval 10
serveralivecountmax 2
`)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case c.hostname != "db.internal.example.com" || c.user != "bob" || c.port != 2222 || c.addr() != "db.internal.example.com:2222":
		t.Errorf("host: %+v", c)
	case c.identities[0] != filepath.Join(home, ".ssh/id_ed25519") || c.identities[1] != filepath.Join(home, ".ssh/db.internal.example.com-bob"):
		t.Errorf("identities: %q", c.identities)
	case c.certs[0] != filepath.Join(home, ".ssh/ca-cert.pub") || c.agent != filepath.Join(home, ".agent.sock"):
		t.Errorf("certs, agent: %q %q", c.certs, c.agent)
	case c.jump != "alice@bastion:2200,jump2" || c.strict != "no" || !c.hashKnown || !c.idOnly:
		t.Errorf("jump, strict, hash, idOnly: %+v", c)
	case len(c.userKnown) != 2 || c.userKnown[1] != "/etc/extra_hosts" || c.globalKnown[0] != "/etc/ssh/ssh_known_hosts":
		t.Errorf("known hosts: %q %q", c.userKnown, c.globalKnown)
	case c.timeout != 7*time.Second || c.alive != 10*time.Second || c.aliveMax != 2:
		t.Errorf("timeouts: %+v", c)
	}
	if c, _ := parseConfig("plain", "port 22\n"); c.hostname != "plain" || c.user == "" || c.strict != "ask" {
		t.Errorf("defaults: %+v", c)
	}
	if d := defaults("h", "", 0, "~/k", "j"); d.port != 22 || d.identities[0] != filepath.Join(home, "k") || d.jump != "j" || len(d.userKnown) != 2 {
		t.Errorf("no ssh binary: %+v", d)
	}
	// The real ssh -G, when there is one: the flags win over ~/.ssh/config.
	if _, err := exec.LookPath("ssh"); err == nil {
		c, err := resolve(context.Background(), "192.0.2.10", "tester", 2022, "", "")
		if err != nil || c.user != "tester" || c.port != 2022 || c.hostname != "192.0.2.10" {
			t.Errorf("ssh -G: %+v %v", c, err)
		}
	}
}

// Arguments reach the remote command exactly, whatever they hold.
func TestShellJoin(t *testing.T) {
	args := []string{"printf", `%s|`, "plain", "with space", "it's", `"dq"`, "$HOME", "`x`", "a\nb", ""}
	out, err := exec.Command("sh", "-c", shellJoin(args)).Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := "plain|with space|it's|\"dq\"|$HOME|`x`|a\nb||"; string(out) != want {
		t.Errorf("%q, want %q", out, want)
	}
}

// setup gives a test its own home (keys, known_hosts) and an SSH server
// that accepts its key; the config is what ssh -G would say for it.
type setup struct {
	t      *testing.T
	home   string
	key    ssh.Signer
	srv    *testServer
	asked  []string
	answer func(q string) (string, error)
}

func newSetup(t *testing.T) *setup {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	_, priv, _ := ed25519.GenerateKey(nil)
	key, _ := ssh.NewSignerFromKey(priv)
	s := &setup{t: t, home: home, key: key, srv: newTestServer(t, key.PublicKey())}
	s.writeKey("id_ed25519", priv, "")
	s.answer = func(string) (string, error) { return "yes", nil }
	ask = func(_ context.Context, q string, _ bool) (string, error) {
		s.asked = append(s.asked, q)
		return s.answer(q)
	}
	resolveConfig = func(_ context.Context, host, user string, port int, identity, jump string) (*hostConfig, error) {
		return s.config(host, port, jump), nil
	}
	t.Cleanup(func() { ask, resolveConfig = transport.Ask, resolve })
	return s
}

func (s *setup) config(host string, port int, jump string) *hostConfig {
	c := defaults(host, "tester", port, "", jump)
	c.identities = []string{filepath.Join(s.home, ".ssh/id_ed25519")}
	c.globalKnown = nil
	return c
}

func (s *setup) writeKey(name string, priv ed25519.PrivateKey, pass string) {
	var block *pem.Block
	var err error
	if pass == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pass))
	}
	if err != nil {
		s.t.Fatal(err)
	}
	dir := filepath.Join(s.home, ".ssh")
	_ = os.MkdirAll(dir, 0o700)
	if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
		s.t.Fatal(err)
	}
}

func (s *setup) knownHosts() string {
	b, _ := os.ReadFile(filepath.Join(s.home, ".ssh/known_hosts"))
	return string(b)
}

func (s *setup) target() Target { return Target{Host: "127.0.0.1", Port: s.srv.port} }

// Commands run on the host, with stdin, output and exit status; a stream
// is the command's stdio.
func TestExec(t *testing.T) {
	s := newSetup(t)
	ctx := context.Background()
	c, err := dial(ctx, s.target(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	ex := &sshExec{client: c.client, desc: c.desc}
	if ex.Describe() != "ssh tester@127.0.0.1:"+fmt.Sprint(s.srv.port) || c.first != c.firstAddr {
		t.Errorf("describe %q, first %q %q", ex.Describe(), c.first, c.firstAddr)
	}
	if out, err := ex.Run(ctx, []string{"sh", "-c", `echo "$1"`, "sh", "it's here"}, nil); err != nil || out != "it's here\n" {
		t.Errorf("run: %q %v", out, err)
	}
	if out, err := ex.Run(ctx, []string{"cat"}, strings.NewReader("from stdin")); err != nil || out != "from stdin" {
		t.Errorf("stdin: %q %v", out, err)
	}
	if _, err := ex.Run(ctx, []string{"sh", "-c", "echo oops >&2; exit 3"}, nil); err == nil || !strings.Contains(err.Error(), "status 3: oops") {
		t.Errorf("exit status: %v", err)
	}
	st, err := ex.Stream(ctx, []string{"cat"}, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintln(st, "ping")
	if line, err := bufio.NewReader(st).ReadString('\n'); err != nil || line != "ping\n" {
		t.Errorf("stream: %q %v", line, err)
	}
	_ = st.Close()
	rctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if _, err := ex.Run(rctx, []string{"sleep", "5"}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("cancelled run: %v", err)
	}
}

// An unknown host key is asked about and saved, then known; refused
// without a yes or a terminal; a changed key is refused without asking.
func TestHostKeys(t *testing.T) {
	s := newSetup(t)
	ctx := context.Background()
	s.answer = func(string) (string, error) { return "", transport.ErrNoTerminal }
	if _, err := dial(ctx, s.target(), quiet); err == nil || !strings.Contains(err.Error(), "no terminal to ask on") {
		t.Errorf("no terminal: %v", err)
	}
	s.answer = func(string) (string, error) { return "no", nil }
	if _, err := dial(ctx, s.target(), quiet); err == nil || !strings.Contains(err.Error(), "wasn't accepted") {
		t.Errorf("no: %v", err)
	}
	s.answer = func(string) (string, error) { return "yes", nil }
	c, err := dial(ctx, s.target(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	c.close()
	fp := ssh.FingerprintSHA256(s.srv.hostKey.PublicKey())
	if q := s.asked[len(s.asked)-1]; !strings.Contains(q, "authenticity of host '[127.0.0.1]:") || !strings.Contains(q, fp) {
		t.Errorf("question: %q", q)
	}
	if kh := s.knownHosts(); !strings.HasPrefix(kh, fmt.Sprintf("[127.0.0.1]:%d ssh-ed25519 ", s.srv.port)) {
		t.Errorf("known_hosts: %q", kh)
	}
	asked := len(s.asked)
	c, err = dial(ctx, s.target(), quiet)
	if err != nil || len(s.asked) != asked {
		t.Errorf("known now: %v, asked %d more", err, len(s.asked)-asked)
	}
	c.close()

	// The same address, another server: a changed key.
	other := newTestServer(t, s.key.PublicKey())
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	otherKey, _ := ssh.NewSignerFromKey(otherPriv)
	line := knownhosts.Line([]string{knownhosts.Normalize(other.addr)}, otherKey.PublicKey())
	_ = os.WriteFile(filepath.Join(s.home, ".ssh/known_hosts"), []byte(line+"\n"), 0o600)
	if _, err := dial(ctx, Target{Host: "127.0.0.1", Port: other.port}, quiet); err == nil || !strings.Contains(err.Error(), "has CHANGED") ||
		!strings.Contains(err.Error(), "ssh-keygen -R") || len(s.asked) != asked {
		t.Errorf("changed key: %v", err)
	}

	// StrictHostKeyChecking yes refuses unknown hosts; accept-new saves them.
	_ = os.Remove(filepath.Join(s.home, ".ssh/known_hosts"))
	for _, tc := range []struct{ strict, wantErr string }{{"yes", "StrictHostKeyChecking is yes"}, {"accept-new", ""}} {
		strict, wantErr := tc.strict, tc.wantErr
		resolveConfig = func(_ context.Context, host, _ string, port int, _, jump string) (*hostConfig, error) {
			c := s.config(host, port, jump)
			c.strict, c.hashKnown = strict, true
			return c, nil
		}
		c, err := dial(ctx, s.target(), quiet)
		switch {
		case wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)):
			t.Errorf("%s: %v", strict, err)
		case wantErr == "" && err != nil:
			t.Errorf("%s: %v", strict, err)
		case wantErr == "":
			c.close()
			if kh := s.knownHosts(); !strings.HasPrefix(kh, "|1|") {
				t.Errorf("hashed: %q", kh)
			}
		}
	}
	if len(s.asked) != asked {
		t.Errorf("asked with StrictHostKeyChecking set: %q", s.asked[asked:])
	}
}

// Keys from the agent; an encrypted key file asks for its passphrase once,
// only when the server takes it; no key: a clear error.
func TestAuth(t *testing.T) {
	s := newSetup(t)
	ctx := context.Background()

	// The agent's key, no key file.
	_ = os.Remove(filepath.Join(s.home, ".ssh/id_ed25519"))
	dir, err := os.MkdirTemp("", "st") // unix socket paths are short
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "a")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ring := agent.NewKeyring()
	_, priv, _ := ed25519.GenerateKey(nil)
	_ = ring.Add(agent.AddedKey{PrivateKey: priv})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(ring, c); _ = c.Close() }()
		}
	}()
	agentKey, _ := ssh.NewSignerFromKey(priv)
	srv := newTestServer(t, agentKey.PublicKey())
	t.Setenv("SSH_AUTH_SOCK", sock)
	c, err := dial(ctx, Target{Host: "127.0.0.1", Port: srv.port}, quiet)
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	c.close()
	t.Setenv("SSH_AUTH_SOCK", "")

	// An encrypted key with its .pub: asked once, when the server takes it.
	_, priv2, _ := ed25519.GenerateKey(nil)
	s.writeKey("id_ed25519", priv2, "secret")
	key2, _ := ssh.NewSignerFromKey(priv2)
	_ = os.WriteFile(filepath.Join(s.home, ".ssh/id_ed25519.pub"), ssh.MarshalAuthorizedKey(key2.PublicKey()), 0o600)
	srv2 := newTestServer(t, key2.PublicKey())
	passes := 0
	s.answer = func(q string) (string, error) {
		if strings.HasPrefix(q, "Enter passphrase") {
			passes++
			if passes == 1 {
				return "wrong", nil
			}
			return "secret", nil
		}
		return "yes", nil
	}
	for i := 0; i < 2; i++ {
		c, err := dial(ctx, Target{Host: "127.0.0.1", Port: srv2.port}, quiet)
		if err != nil {
			t.Fatalf("encrypted key: %v", err)
		}
		c.close()
	}
	if passes != 2 {
		t.Errorf("passphrase asked %d times (one wrong, then once for the run)", passes)
	}
	unlocked.Clear()

	// A server that takes another key: the locked key's passphrase isn't
	// asked at all.
	passes = 0
	if _, err := dial(ctx, Target{Host: "127.0.0.1", Port: s.srv.port}, quiet); err == nil || passes != 0 {
		t.Errorf("not taken: %v, asked %d", err, passes)
	}

	// No keys at all.
	_ = os.Remove(filepath.Join(s.home, ".ssh/id_ed25519"))
	if _, err := dial(ctx, s.target(), quiet); err == nil || !strings.Contains(err.Error(), "no SSH keys") {
		t.Errorf("no keys: %v", err)
	}
}

// Through a jump host: logins on both, the TCP connection to the jump
// host only.
func TestJump(t *testing.T) {
	s := newSetup(t)
	jump := newTestServer(t, s.key.PublicKey())
	c, err := dial(context.Background(), Target{Host: "127.0.0.1", Port: s.srv.port, Jump: jump.addr}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if c.first != jump.addr || len(c.hops) != 1 || jump.loginCount() != 1 || s.srv.loginCount() != 1 {
		t.Errorf("first %q, hops %d, logins %d %d", c.first, len(c.hops), jump.loginCount(), s.srv.loginCount())
	}
	ex := &sshExec{client: c.client}
	if out, err := ex.Run(context.Background(), []string{"echo", "through"}, nil); err != nil || out != "through\n" {
		t.Errorf("run: %q %v", out, err)
	}
	if !strings.Contains(c.desc, "via "+jump.addr) {
		t.Errorf("desc %q", c.desc)
	}
	if ep, err := Endpoint(Target{Host: "127.0.0.1", Port: s.srv.port, Jump: jump.addr}); err != nil || ep != jump.addr {
		t.Errorf("endpoint %q %v", ep, err)
	}
}

// ProxyCommand: SSH over a command's stdio (here this test binary, relaying
// to the server); no endpoint is known.
func TestProxyCommand(t *testing.T) {
	s := newSetup(t)
	resolveConfig = func(_ context.Context, host, _ string, port int, _, jump string) (*hostConfig, error) {
		c := s.config(host, port, jump)
		c.proxyCmd = fmt.Sprintf("env SUBTUN_TEST_RELAY=%%h:%%p %q -test.run=TestRelayHelper", os.Args[0]) // OpenSSH runs it after exec too
		return c, nil
	}
	c, err := dial(context.Background(), s.target(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if out, err := (&sshExec{client: c.client}).Run(context.Background(), []string{"echo", "proxied"}, nil); err != nil || out != "proxied\n" {
		t.Errorf("run: %q %v", out, err)
	}
	if ep, err := Endpoint(s.target()); err != nil || ep != "" || c.first != "" {
		t.Errorf("endpoint %q %v, first %q", ep, err, c.first)
	}
}

// TestRelayHelper is the proxy command of TestProxyCommand: stdin and
// stdout to SUBTUN_TEST_RELAY.
func TestRelayHelper(t *testing.T) {
	addr := os.Getenv("SUBTUN_TEST_RELAY")
	if addr == "" {
		t.Skip("only as a proxy command")
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		os.Exit(1)
	}
	go func() { _, _ = bufio.NewReader(os.Stdin).WriteTo(c); _ = c.(*net.TCPConn).CloseWrite() }()
	_, _ = bufio.NewReader(c).WriteTo(os.Stdout)
	os.Exit(0)
}

// The whole connect: the agent starts on the host (here: this machine, so
// the Python agent when it isn't Linux) and closing the carrier ends the
// connection.
func TestConnect(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	s := newSetup(t)
	carrier, err := Connect(context.Background(), s.target(), nil, transport.Options{Agent: transport.AgentPython}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if carrier.Host != s.srv.addr || len(carrier.Endpoints) != 1 || carrier.Endpoints[0].String() != "127.0.0.1" || !carrier.Local {
		t.Errorf("carrier: %+v", carrier)
	}
	if !strings.Contains(carrier.Desc, "ssh tester@127.0.0.1") {
		t.Errorf("desc %q", carrier.Desc)
	}
	_ = carrier.Close()
}
