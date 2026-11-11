# subnet-tunnel (`subtun`)

Route chosen subnets and DNS domains from your laptop through a remote host, Kubernetes pod or
Docker container, as if you were on that network. A single static Go binary: no Python, no
runtime dependencies, nothing to install on the far side.

Inspired by [sshuttle](https://github.com/sshuttle/sshuttle). Built because on macOS sshuttle's
pf-based capture caps upload at a few MB/s, while a utun interface with a userspace TCP/IP stack
reached ~170 MB/s end to end in the same test (see [docs/design.md](docs/design.md)).

> **Status:** early development. Kubernetes and Docker targets work through a local SOCKS5 proxy.
> Transparent capture (utun + gVisor, routes, split DNS) is next.

## Build

Needs Go (version in [go.mod](go.mod)), `make` and `git`. No C toolchain: everything builds with
`CGO_ENABLED=0`.

```sh
git clone https://github.com/md2k/subnet-tunnel.git && cd subnet-tunnel
make            # runs the tests, then builds build/subtun with the Linux agents embedded
build/subtun version
```

| Target | What it does |
|---|---|
| `make` | `make test` then `make build` |
| `make build` | Linux agents (amd64, arm64) → `internal/agentbin/dist/`, then `build/subtun` for this machine |
| `make test` | unit tests (`make test-race` adds the race detector, needs a C toolchain) |
| `make lint` | `go vet` and a gofmt check |
| `make release VERSION=v0.1.0 ARGS="--dry-run"` | builds archives for macOS, Linux and Windows (amd64, arm64) in `build/release/`, without tagging or publishing |
| `make release VERSION=v0.1.0` | the same, then tags and publishes a GitHub release (from an up-to-date `main` only) |
| `make clean` / `make clean-all` | remove the binaries / everything under `build/` |

To run on another machine without building there, take its archive from `build/release/` after a
dry run.

## Use

```sh
# Kubernetes: any running pod whose container has sh, uname and cat
build/subtun k8s -n team-a debug-pod --socks 127.0.0.1:1080

# Docker: same for a container
build/subtun docker my-app --socks 127.0.0.1:1080

curl --socks5-hostname 127.0.0.1:1080 http://my-svc.team-a.svc.cluster.local
```

subtun connects with your kubeconfig or Docker context, uploads a small agent over exec (cached in
the target by checksum) and opens connections from inside the target. Hostnames resolve there too.
No `kubectl port-forward`, no sshd, no second terminal.

The target container needs Linux on amd64 or arm64, `sh` with the basic tools (`uname`, `cat`,
`mkdir`, `chmod`, `mv`; busybox is enough) and a writable directory that allows exec: `/tmp` by
default, or `--agent-dir` (for example an emptyDir) when the root filesystem is read-only. Images
without a shell (distroless, scratch) are not supported yet.

## Planned

- Capture through a TUN interface (utun on macOS, TUN on Linux, wintun on Windows) with the
  [gVisor](https://gvisor.dev) userspace network stack. No pf or iptables redirects.
- Split routing: only the CIDRs you list go through the tunnel.
- Split DNS: only the domains you list resolve through the tunnel.
- SSH transport to any host.
- Runs as your user. sudo is requested only for the steps that need root (interface, routes,
  resolver entries).

## Documentation

- [Design](docs/design.md): measurements, architecture and open questions.
- [Development](docs/development.md): tests, code layout and the local test setup.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).
