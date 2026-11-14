package transport

import "sync"

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
