package transport

import "testing"

// Picked keeps a pick, or a created one with its ID, and pins where the
// target is at the first connect only.
func TestPicked(t *testing.T) {
	var none *Picked
	none.Set("x")
	none.Pin("a", "b")
	if none.Get() != "" {
		t.Error("nil remembered")
	}
	p := &Picked{}
	p.SetCreated("subtun-x", "uid-1")
	if n, id := p.Created(); n != "subtun-x" || id != "uid-1" {
		t.Errorf("created: %q %q", n, id)
	}
	p.Set("pod-a") // a pick has no ID
	if _, id := p.Created(); id != "" || p.Get() != "pod-a" {
		t.Errorf("picked: %q %q", p.Get(), id)
	}
	if _, _, ok := p.Pinned(); ok {
		t.Error("pinned before the first connect")
	}
	p.Pin("ctx-1", "ops")
	p.Pin("ctx-2", "other") // a later context switch doesn't move it
	if a, b, ok := p.Pinned(); !ok || a != "ctx-1" || b != "ops" {
		t.Errorf("pinned: %q %q %v", a, b, ok)
	}
}
