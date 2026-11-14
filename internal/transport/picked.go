package transport

import "sync"

// DefaultImage is what a pod or container subtun creates runs, unless the
// target says: it needs a shell, for the agent's upload.
const DefaultImage = "busybox:1.37"

// Picked remembers the pod or container a followed target (a Deployment,
// labels) used last: it is picked again while it can still be used, so
// the agent cached there is reused. The zero value and nil remember
// nothing.
type Picked struct {
	mu   sync.Mutex
	name string
}

// Get returns the name picked last; "": none.
func (p *Picked) Get() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.name
}

// Set remembers name.
func (p *Picked) Set(name string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.name = name
	p.mu.Unlock()
}
