package ssh

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/md2k/subnet-tunnel/internal/transport"
)

// hostKeys checks a server's host key against the known_hosts files
// (UserKnownHostsFile, GlobalKnownHostsFile; @cert-authority and @revoked
// lines too). An unknown host is asked about on the terminal and saved, as
// OpenSSH does (StrictHostKeyChecking ask; yes refuses it, accept-new and
// no save it without asking). A changed key is always refused.
type hostKeys struct {
	ctx   context.Context
	c     *hostConfig
	log   *slog.Logger
	check ssh.HostKeyCallback // nil: no known_hosts file yet
}

func newHostKeys(ctx context.Context, c *hostConfig, log *slog.Logger) (*hostKeys, error) {
	h := &hostKeys{ctx: ctx, c: c, log: log}
	var files []string
	for _, f := range append(append([]string(nil), c.userKnown...), c.globalKnown...) {
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}
	if len(files) > 0 {
		cb, err := knownhosts.New(files...)
		if err != nil {
			return nil, fmt.Errorf("reading known_hosts: %w", err)
		}
		h.check = cb
	}
	return h, nil
}

// algorithms are the host key types known_hosts has for addr, so the server
// is asked for one of them (else it may offer another type of its keys,
// which then looks like a changed key). None known: the defaults.
func (h *hostKeys) algorithms(addr string) []string {
	if h.check == nil {
		return nil
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	probe, _ := ssh.NewPublicKey(pub)
	var ke *knownhosts.KeyError
	if err := h.check(addr, &net.TCPAddr{IP: net.IPv4zero}, probe); !errors.As(err, &ke) || len(ke.Want) == 0 {
		return nil
	}
	var algos []string
	seen := map[string]bool{}
	for _, k := range ke.Want {
		t := k.Key.Type()
		names := []string{t}
		if t == ssh.KeyAlgoRSA {
			names = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
		}
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				algos = append(algos, n)
			}
		}
	}
	return algos
}

// callback checks the key a server at addr (host:port) sends.
func (h *hostKeys) callback(addr string, remote net.Addr, key ssh.PublicKey) error {
	err := &knownhosts.KeyError{}
	var checkErr error = err
	if h.check != nil {
		checkErr = h.check(addr, remote, key)
	}
	if checkErr == nil {
		return nil
	}
	host := knownhosts.Normalize(addr)
	var revoked *knownhosts.RevokedError
	if errors.As(checkErr, &revoked) {
		return fmt.Errorf("the host key of %s is revoked (%s)", host, revoked.Revoked.Filename)
	}
	if !errors.As(checkErr, &err) {
		return checkErr
	}
	fp := ssh.FingerprintSHA256(key)
	if len(err.Want) > 0 {
		w := err.Want[0]
		return fmt.Errorf("the host key of %s has CHANGED: known_hosts (%s:%d) has %s %s, the server sent %s %s; "+
			"if the change is expected, remove the old key with: ssh-keygen -R '%s'",
			host, w.Filename, w.Line, w.Key.Type(), ssh.FingerprintSHA256(w.Key), key.Type(), fp, host)
	}
	switch h.c.strict {
	case "yes":
		return fmt.Errorf("the host key of %s (%s %s) isn't in known_hosts and StrictHostKeyChecking is yes: "+
			"connect once with ssh %s to check and accept it", host, key.Type(), fp, h.c.alias)
	case "ask":
		ip := ""
		if ta, ok := remote.(*net.TCPAddr); ok && !ta.IP.IsUnspecified() && ta.IP.String() != h.c.hostname {
			ip = " (" + ta.IP.String() + ")"
		}
		answer, aerr := ask(h.ctx, fmt.Sprintf("The authenticity of host '%s%s' can't be established.\n"+
			"%s key fingerprint is %s.\nAre you sure you want to continue connecting (yes/no)? ", host, ip, key.Type(), fp), false)
		switch {
		case errors.Is(aerr, transport.ErrNoTerminal):
			return fmt.Errorf("the host key of %s (%s %s) isn't in known_hosts and there's no terminal to ask on: "+
				"connect once with ssh %s to check and accept it", host, key.Type(), fp, h.c.alias)
		case aerr != nil:
			return aerr
		case !strings.EqualFold(answer, "yes"):
			return fmt.Errorf("the host key of %s wasn't accepted", host)
		}
	}
	if err := h.save(addr, key); err != nil {
		h.log.Warn("couldn't save the host key to known_hosts; it will be asked again next time", "host", host, "err", err)
	} else {
		h.log.Info("host key added to known_hosts", "host", host, "key", key.Type()+" "+fp)
	}
	return nil
}

// save appends addr's key to the first user known_hosts file.
func (h *hostKeys) save(addr string, key ssh.PublicKey) error {
	if len(h.c.userKnown) == 0 {
		return errors.New("no UserKnownHostsFile")
	}
	path := h.c.userKnown[0]
	name := knownhosts.Normalize(addr)
	if h.c.hashKnown {
		name = knownhosts.HashHostname(name)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(f, knownhosts.Line([]string{name}, key))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
