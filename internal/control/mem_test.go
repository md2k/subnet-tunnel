package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/logring"
)

func TestInMemory(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := testServer()
	c := srv.InMemory(ctx)

	var st Status
	if err := c.Get(ctx, "/v1/status", &st); err != nil || st.PID != 42 {
		t.Fatalf("status: %+v %v", st, err)
	}
	// Read only: refused with the reason, as on the socket.
	var res Result
	if err := c.Post(ctx, "/v1/routes", Change{Op: "add", CIDRs: []string{"10.0.0.0/8"}}, &res); err == nil || !strings.Contains(err.Error(), "read only") {
		t.Fatalf("change on a read-only server: %v", err)
	}

	// The log stream follows new lines, and ends when ctx does.
	got := make(chan string, 8)
	streamed := make(chan error, 1)
	go func() {
		streamed <- c.Stream(ctx, "/v1/logs?follow=1", func(b []byte) error {
			var l logring.Line
			if err := json.Unmarshal(b, &l); err != nil {
				return err
			}
			got <- l.Text
			return nil
		})
	}()
	for _, want := range []string{"line 1", "line 2"} {
		if l := <-got; l != want {
			t.Fatalf("held line %q, want %q", l, want)
		}
	}
	srv.Logs.Add(logring.Line{Text: "line 3"})
	select {
	case l := <-got:
		if l != "line 3" {
			t.Fatalf("new line %q", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("new line not streamed")
	}
	cancel()
	select {
	case <-streamed:
	case <-time.After(5 * time.Second):
		t.Fatal("stream didn't end with ctx")
	}
	if err := c.Get(context.Background(), "/v1/status", &st); err == nil {
		t.Fatal("answered after ctx ended")
	}
}
