package transport

import "sync"

// DefaultImage is what a pod or container subtun creates runs, unless the
// target says: it needs a shell, for the agent's upload.
const DefaultImage = "busybox:1.37"

// Picked is what a profile's target found or made, kept across its
// connects:
//   - the pod or container picked last (a selector's choice: picked again
//     while it can still be used, so the agent cached there is reused);
//   - the one subtun created, with its UID or ID, so only that one is ever
//     deleted;
//   - where it is (the kube context and namespace, or the Docker host),
//     fixed at the first connect: switching contexts meanwhile doesn't move
//     the run.
//
// The zero value and nil remember nothing.
type Picked struct {
	mu       sync.Mutex
	name, id string
	pinned   bool
	pinA     string // kube context, or Docker host
	pinB     string // namespace
}

// Get returns the name picked or created last; "": none.
func (p *Picked) Get() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.name
}

// Set remembers a picked name (not one subtun created).
func (p *Picked) Set(name string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.name, p.id = name, ""
	p.mu.Unlock()
}

// SetCreated remembers the pod or container subtun created: its name and
// UID or ID ("", "": none any more).
func (p *Picked) SetCreated(name, id string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.name, p.id = name, id
	p.mu.Unlock()
}

// Created returns the pod or container subtun created, and its UID or ID;
// id "": none.
func (p *Picked) Created() (name, id string) {
	if p == nil {
		return "", ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.name, p.id
}

// Pinned returns where the target was found at its first connect; ok
// false: not connected yet.
func (p *Picked) Pinned() (a, b string, ok bool) {
	if p == nil {
		return "", "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pinA, p.pinB, p.pinned
}

// Pin fixes where the target is, the first time only.
func (p *Picked) Pin(a, b string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if !p.pinned {
		p.pinA, p.pinB, p.pinned = a, b, true
	}
	p.mu.Unlock()
}
