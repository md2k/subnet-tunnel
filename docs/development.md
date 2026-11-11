# Development

## Build and test

```sh
make            # builds the Linux agents, embeds them, writes bin/subtun
make test       # go test -race ./...
make vet
```

`make agents` cross-compiles `cmd/subtun-agent` for linux/amd64 and linux/arm64 into
`internal/agentbin/dist/`, where `go:embed` picks them up. A plain `go build ./cmd/subtun` works
without them, but then subtun has no agent to upload; pass `--agent-file` (hidden flag) with a
Linux build of `cmd/subtun-agent` instead.

Unit tests use in-memory connections and stub dialers. They open no sockets.

## Layout

| Path | What |
|---|---|
| `cmd/subtun` | the CLI |
| `cmd/subtun-agent` | the remote agent (Linux, static) |
| `internal/proto` | hello line, per-stream request/response, smux settings |
| `internal/agent` | agent side: serve smux on stdio, dial on request |
| `internal/tunnel` | laptop side: check the hello, open streams through the agent |
| `internal/transport` | get the agent running in a target (probe, upload, start) |
| `internal/transport/k8s`, `.../docker` | exec into a pod / container |
| `internal/socks` | SOCKS5 frontend |
| `internal/relay` | bidirectional copy with half-close |
| `test/dev` | local test setup for both targets |

## Local test setup

`test/dev` has a `target` (plain Alpine, where the agent runs) and a `web` service reached through
it. `web.py` serves `GET /bytes/N` (N zero bytes) and discards `PUT`/`POST` bodies, for throughput.

Kubernetes (Docker Desktop, kind, ...):

```sh
kubectl apply -k test/dev
kubectl -n subtun-dev wait --for=condition=Ready pod --all
bin/subtun k8s -n subtun-dev target --socks 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 http://web.subtun-dev.svc.cluster.local:8080/
kubectl delete namespace subtun-dev
```

Docker:

```sh
docker compose -f test/dev/compose.yaml up -d
bin/subtun docker subtun-dev-target-1 --socks 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 http://web:8080/
docker compose -f test/dev/compose.yaml down
```

If the Kubernetes node can't pull images (for example behind a TLS-inspecting proxy), pull them
with `docker pull alpine:3.20 python:3.12-alpine` first; Docker Desktop's node gets them through
its registry mirror.

Throughput, through the proxy:

```sh
curl --socks5-hostname 127.0.0.1:1080 -o /dev/null -w '%{speed_download}\n' http://web:8080/bytes/524288000
dd if=/dev/zero of=bin/bench.dat bs=1048576 count=500
curl --socks5-hostname 127.0.0.1:1080 -o /dev/null -T bin/bench.dat -w '%{speed_upload}\n' http://web:8080/up
```
