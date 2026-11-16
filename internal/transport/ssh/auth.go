package ssh

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// auth is how subtun logs in: keys from the agent, then key files
// (IdentityFile), with certificates (CertificateFile, or a key's
// -cert.pub). No passwords. An encrypted key file asks for its passphrase
// only when the server accepts its public key, once per run.
type auth struct {
	signers []ssh.Signer
	agent   net.Conn
}

func (a *auth) close() {
	if a.agent != nil {
		_ = a.agent.Close()
	}
}

func (a *auth) method() ssh.AuthMethod { return ssh.PublicKeys(a.signers...) }

func newAuth(ctx context.Context, c *hostConfig, log *slog.Logger) (*auth, error) {
	a := &auth{}
	var fromAgent []ssh.Signer
	if sock := agentSocket(c.agent); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			log.Debug("no SSH agent", "socket", sock, "err", err)
		} else {
			a.agent = conn
			if fromAgent, err = agent.NewClient(conn).Signers(); err != nil {
				log.Debug("listing the SSH agent's keys", "err", err)
			}
		}
	}
	var fromFiles []ssh.Signer
	for _, path := range c.identities {
		s, err := fileSigner(ctx, path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			log.Warn("skipping an SSH key", "file", path, "err", err)
			continue
		}
		fromFiles = append(fromFiles, s)
	}
	// OpenSSH's order: the configured key files first (signed by the agent
	// when it has the same key: no passphrase), then the agent's other keys
	// (none with IdentitiesOnly). A server counts every key offered against
	// its MaxAuthTries.
	var all []ssh.Signer
	for _, f := range fromFiles {
		s := f
		for _, a := range fromAgent {
			if bytes.Equal(a.PublicKey().Marshal(), f.PublicKey().Marshal()) {
				s = a
				break
			}
		}
		if !hasKey(all, s.PublicKey()) {
			all = append(all, s)
		}
	}
	if !c.idOnly {
		for _, s := range fromAgent {
			if !hasKey(all, s.PublicKey()) {
				all = append(all, s)
			}
		}
	}
	// Certificates first: a server trusting the CA takes them.
	var certs []ssh.Signer
	certFiles := append([]string(nil), c.certs...)
	for _, path := range c.identities {
		certFiles = append(certFiles, path+"-cert.pub")
	}
	for _, path := range certFiles {
		cert, err := readCert(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Warn("skipping an SSH certificate", "file", path, "err", err)
			}
			continue
		}
		for _, s := range all {
			if bytes.Equal(s.PublicKey().Marshal(), cert.Key.Marshal()) {
				if cs, err := ssh.NewCertSigner(cert, s); err == nil && !hasKey(certs, cs.PublicKey()) {
					certs = append(certs, cs)
				}
				break
			}
		}
	}
	a.signers = append(certs, all...)
	if len(a.signers) == 0 {
		a.close()
		return nil, errors.New("no SSH keys: none in the agent ($SSH_AUTH_SOCK) and no key files (IdentityFile, ~/.ssh/id_*); subtun logs in with keys only")
	}
	return a, nil
}

// agentSocket is IdentityAgent's socket: SSH_AUTH_SOCK (or "$NAME") for
// the environment's, none for no agent.
func agentSocket(v string) string {
	switch {
	case v == "none":
		return ""
	case v == "" || v == "SSH_AUTH_SOCK":
		return os.Getenv("SSH_AUTH_SOCK")
	case strings.HasPrefix(v, "$"):
		return os.Getenv(strings.Trim(v[1:], "{}"))
	}
	return v
}

func hasKey(list []ssh.Signer, k ssh.PublicKey) bool {
	for _, s := range list {
		if bytes.Equal(s.PublicKey().Marshal(), k.Marshal()) {
			return true
		}
	}
	return false
}

func readCert(path string) (*ssh.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil, err
	}
	cert, ok := k.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not a certificate")
	}
	return cert, nil
}

// unlocked keeps the keys whose passphrase was given, for the run: a
// reconnect doesn't ask again.
var unlocked sync.Map // path → ssh.Signer

// fileSigner reads a private key file. An encrypted one with its public
// key next to it (KEY.pub) asks for the passphrase when it first signs;
// without one, now.
func fileSigner(ctx context.Context, path string) (ssh.Signer, error) {
	if s, ok := unlocked.Load(path); ok {
		return s.(ssh.Signer), nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := ssh.ParsePrivateKey(pem)
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return s, err
	}
	pub := missing.PublicKey
	if pub == nil {
		if b, err := os.ReadFile(path + ".pub"); err == nil {
			pub, _, _, _, _ = ssh.ParseAuthorizedKey(b)
		}
	}
	l := &lockedKey{ctx: context.WithoutCancel(ctx), path: path, pem: pem, pub: pub}
	if pub == nil {
		return l.unlock()
	}
	return l, nil
}

// lockedKey is an encrypted key that asks for its passphrase when it's
// first used to sign.
type lockedKey struct {
	ctx  context.Context
	path string
	pem  []byte
	pub  ssh.PublicKey
	mu   sync.Mutex
}

func (l *lockedKey) unlock() (ssh.Signer, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := unlocked.Load(l.path); ok {
		return s.(ssh.Signer), nil
	}
	for try := 0; try < 3; try++ {
		pass, err := ask(l.ctx, fmt.Sprintf("Enter passphrase for key '%s': ", l.path), true)
		if err != nil {
			return nil, fmt.Errorf("the passphrase for %s: %w", l.path, err)
		}
		s, err := ssh.ParsePrivateKeyWithPassphrase(l.pem, []byte(pass))
		if err == nil {
			unlocked.Store(l.path, s)
			return s, nil
		}
		if !errors.Is(err, x509.IncorrectPasswordError) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%s: wrong passphrase", l.path)
}

func (l *lockedKey) PublicKey() ssh.PublicKey { return l.pub }

func (l *lockedKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	s, err := l.unlock()
	if err != nil {
		return nil, err
	}
	return s.Sign(rand, data)
}

// SignWithAlgorithm lets RSA keys sign with rsa-sha2-256/512 (servers
// refuse ssh-rsa's SHA-1).
func (l *lockedKey) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	s, err := l.unlock()
	if err != nil {
		return nil, err
	}
	if as, ok := s.(ssh.AlgorithmSigner); ok {
		return as.SignWithAlgorithm(rand, data, algorithm)
	}
	return s.Sign(rand, data)
}
