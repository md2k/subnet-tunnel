# subnet-tunnel (`subtun`)

Route chosen subnets and DNS domains from your laptop through a remote host, Kubernetes pod or
Docker container, as if you were on that network. A single static Go binary: no Python, no
runtime dependencies, nothing to install on the far side.

Inspired by [sshuttle](https://github.com/sshuttle/sshuttle). Built because on macOS sshuttle's
pf-based capture caps upload at a few MB/s, while a utun interface with a userspace TCP/IP stack
reached ~170 MB/s end to end in the same test (see [docs/design.md](docs/design.md)).

> **Status:** early development. Kubernetes and Docker targets, transparent capture of CIDRs on
> macOS (utun + gVisor) and a SOCKS5 proxy. Split DNS is next.

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
# Capture CIDRs (or single IPs): every program on this machine reaches them directly (macOS)
build/subtun k8s -n team-a debug-pod 10.96.0.0/12 10.244.0.0/16
curl http://10.96.12.34:8080/

# SOCKS5 proxy, for example for a browser; hostnames resolve inside the target
build/subtun k8s -n team-a debug-pod --socks 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 http://my-svc.team-a.svc.cluster.local

# Both at once, and the same for a Docker container
build/subtun docker my-app 172.20.0.0/16 --socks 127.0.0.1:1080
```

subtun connects with your kubeconfig or Docker context, starts a small agent in the target over exec
and opens connections from inside the target. No `kubectl port-forward`, no sshd, no second
terminal.

**Capture and root.** subtun runs as your user. With CIDRs, sudo asks for your password once: a
short-lived helper creates a utun interface (MTU 9000), adds routes for your CIDRs, hands the
interface to subtun and exits. Traffic is only ever handled by the subtun process running as you.
The routes live and die with the interface: when subtun exits, crashes or is killed, macOS removes
both, so nothing is left behind. To change CIDRs, restart subtun. See
[Privileges](docs/design.md#privileges) for how this works and the planned session mode for
changes without a restart.

Two agents speak the same protocol; `--agent auto` (the default) picks the first that can run:

| `--agent` | Target needs | Writes to the target |
|---|---|---|
| `binary` | Linux amd64/arm64, `sh` with basic tools (busybox is enough), a writable directory that allows exec | one cached ~3.5 MB binary in a private directory: `~/.cache/subtun`, else `/tmp/subtun-<uid>`, `/var/tmp/subtun-<uid>`, `/dev/shm/subtun-<uid>`, or `--agent-dir` |
| `python` | Python 3.6+ (no shell needed) | nothing: the source is sent over exec and run from memory, like sshuttle |

Both reach about the same speed in our tests. Images with neither a shell nor Python (distroless
static, scratch) are not supported yet.

**Excludes and profiles.** `-x/--exclude` keeps addresses out of the tunnel; the most specific rule
wins, like sshuttle. `--dry-run` prints the routes subtun would install. Settings can live in named
profiles in `~/.config/subtun/config.yaml`:

```yaml
profiles:
  dev-cluster:
    target: {k8s: {context: dev, namespace: tools, pod: debug}}
    routes: [10.0.0.0/8, 172.16.0.0/12]
    exclude: [10.1.0.0/16]
    socks: 127.0.0.1:1080
```

```sh
build/subtun up dev-cluster            # flags still override, extra CIDRs and -x are added
```

See [Configuration](docs/config.md).

## Planned

- Split DNS: only the domains you list resolve through the tunnel.
- SSH transport to any host.
- Capture on Linux (TUN) and Windows (wintun); IPv6 and UDP.
- Session mode for the root helper: change CIDRs and DNS at runtime without a restart (opt-in).

## Documentation

- [Configuration](docs/config.md): profiles, routes and excludes, safety checks.
- [Design](docs/design.md): measurements, architecture and open questions.
- [Development](docs/development.md): tests, code layout and the local test setup.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).
