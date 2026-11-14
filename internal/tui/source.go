package tui

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/logring"
)

// Source is a running subtun: its control socket, or a fake in tests.
type Source interface {
	Status(ctx context.Context) (control.Status, error)
	// Samples returns each tunnel's samples (the last 5 minutes).
	Samples(ctx context.Context) ([]control.TunnelSamples, error)
	Conns(ctx context.Context) ([]control.TunnelConns, error)
	Config(ctx context.Context) (control.ConfigProfiles, error)
	// Logs calls fn with the log lines held, then with new ones, until ctx
	// ends or the stream does.
	Logs(ctx context.Context, fn func(logring.Line)) error
	// Change makes a change; c.Kind picks the endpoint.
	Change(ctx context.Context, c control.Change) (control.Result, error)
}

// Socket is the Source of the subtun whose control socket is at path.
func Socket(path string) Source { return API(control.NewClient(path)) }

// API is the Source a control API client talks to: a socket's, or the
// in-memory one of subtun itself (control.Server.InMemory).
func API(c *control.Client) Source { return socket{c} }

type socket struct{ c *control.Client }

func (s socket) Status(ctx context.Context) (control.Status, error) {
	var st control.Status
	err := s.c.Get(ctx, "/v1/status", &st)
	return st, err
}

func (s socket) Samples(ctx context.Context) ([]control.TunnelSamples, error) {
	var out []control.TunnelSamples
	err := s.c.Get(ctx, "/v1/samples", &out)
	return out, err
}

func (s socket) Conns(ctx context.Context) ([]control.TunnelConns, error) {
	var out []control.TunnelConns
	err := s.c.Get(ctx, "/v1/connections", &out)
	return out, err
}

func (s socket) Config(ctx context.Context) (control.ConfigProfiles, error) {
	var out control.ConfigProfiles
	err := s.c.Get(ctx, "/v1/config", &out)
	return out, err
}

func (s socket) Logs(ctx context.Context, fn func(logring.Line)) error {
	return s.c.Stream(ctx, "/v1/logs?follow=1", func(b []byte) error {
		var l logring.Line
		if err := json.Unmarshal(b, &l); err != nil {
			return err
		}
		fn(l)
		return nil
	})
}

func (s socket) Change(ctx context.Context, c control.Change) (control.Result, error) {
	endpoint := map[string]string{control.KindRoute: "/v1/routes", control.KindDNS: "/v1/dns", control.KindProfile: "/v1/profiles", control.KindLog: "/v1/log"}[c.Kind]
	if endpoint == "" {
		return control.Result{}, fmt.Errorf("unknown change kind %q", c.Kind)
	}
	var res control.Result
	err := s.c.Post(ctx, endpoint, c, &res)
	return res, err
}
