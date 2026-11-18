# subnet-tunnel (`subtun`)

Route chosen subnets and DNS domains from your laptop through a Kubernetes pod, a Docker container
or a host over SSH, as if you were on that network. A single static Go binary: no Python, no
runtime dependencies, nothing to install on the far side.

Inspired by [sshuttle](https://github.com/sshuttle/sshuttle). Built because on macOS sshuttle's
pf-based capture caps upload at a few MB/s, while a utun interface with a userspace TCP/IP stack
reached ~170 MB/s end to end in the same test (see [docs/design.md](docs/design.md)).

> **Status:** early development, macOS; Linux (Debian, Ubuntu) has the capture of CIDRs and a full
> tunnel, not yet split DNS, the kill switch or the IPv6 block. Kubernetes, Docker and SSH targets;
> transparent capture of CIDRs or a full tunnel (TUN + gVisor), split DNS, a kill switch, several
> profiles at once, a SOCKS5 proxy, status and a terminal UI.

## Quick start

```sh
git clone https://github.com/md2k/subnet-tunnel.git && cd subnet-tunnel
make                      # tests, then build/subtun with its agents embedded (needs Go and make)
```

Through a pod subtun creates for the run (and deletes on stop), with the cluster's names:

```sh
build/subtun up --k8s --context dev -n team-a 10.96.0.0/12 10.244.0.0/16 --dns-domain cluster.local
curl http://my-svc.team-a.svc.cluster.local:8080/        # any program reaches them directly
```

Through a host over SSH, as with sshuttle (your `~/.ssh/config`, keys and agent):

```sh
build/subtun up --ssh me@gw.example.com 10.20.0.0/16
build/subtun up --ssh db-host -J me@bastion.example.com 10.30.0.0/16     # through a jump host
```

Everything through a remote host, every name resolved there, nothing leaking if the tunnel goes:

```sh
build/subtun up --ssh me@bastion.example.com 0.0.0.0/1 128.0.0.0/1 --dns-domain . --kill-switch on
```

A SOCKS5 proxy only, no root needed; here through an existing pod and a Docker container:

```sh
build/subtun up --k8s -n team-a --create=false --name debug-pod --socks 127.0.0.1:1080
build/subtun up --docker --network my-app_default --socks 127.0.0.1:1081
curl --socks5-hostname 127.0.0.1:1080 http://my-svc.team-a.svc.cluster.local
```

Profiles in `~/.config/subtun/config.yaml`, one at a time or several at once:

```yaml
profiles:
  dev:
    target: {k8s: {context: dev, namespace: team-a}}
    routes: [10.96.0.0/12, 10.244.0.0/16]
    dns: {domains: [cluster.local]}
  office:
    target: {ssh: {host: me@gw.example.com, jump: me@bastion.example.com}}
    routes: [10.20.0.0/16]
    dns: {domains: [corp.example.com]}
    killSwitch: {mode: on}
```

```sh
build/subtun up dev --dry-run          # what it would do, without root
build/subtun up --profile dev,office   # both: each connection goes to the profile that routes it
build/subtun up office --tui           # with the terminal UI in the same terminal
build/subtun status                    # in another terminal: tunnels, routes, DNS, traffic
```

More examples: [Configuration → Examples](docs/config.md#examples).

## What it does

- **Targets** ([details](docs/config.md#targets)): a pod subtun creates or an existing one (by name
  or labels), a container likewise, or a host over SSH (jump hosts, proxy commands, known_hosts as
  `ssh` keeps it, keys only). subtun starts a small agent there over exec or an SSH session: a Go
  binary, or a Python one where the binary can't run.
- **Capture** ([routes](docs/config.md#routes-and-excludes), [full tunnel](docs/config.md#full-tunnel)):
  your CIDRs go through a utun interface, TCP and UDP (QUIC too), so every program reaches them
  directly. Root only for a short-lived helper that sets up the interface and routes
  ([privileges](docs/design.md#privileges)); everything else runs as you. Excludes win by being more specific; your LAN and subtun's own
  connection are excluded automatically; routing loops are caught.
- **Split DNS** ([DNS](docs/config.md#dns)): names under your domains or patterns resolve inside the
  target, the rest as before; `--dns-domain .` sends every name but local ones.
- **Kill switch** ([details](docs/config.md#kill-switch)): traffic for your routes can't leave another
  way when the tunnel is gone; IPv6 is blocked in a full tunnel.
- **Reconnect** ([details](docs/config.md#reconnect)): routes, DNS and the proxy stay while subtun
  connects again; a pod or container it created is reused, or created again.
- **Several profiles at once** ([details](docs/config.md#several-profiles-at-once)), each with its own
  target, routes, DNS names and kill switch.
- **Status, logs, changes while running** ([status](docs/config.md#status-and-logs),
  [log files](docs/config.md#log-files), [changes](docs/config.md#changes-while-running)): `subtun
  status`, `subtun logs -f`, JSON log files; with `--control full`, routes, DNS names and profiles
  change without a restart.
- **Terminal UI** ([details](docs/config.md#terminal-ui)): `subtun tui` attaches to a running subtun;
  `up --tui` runs it in subtun's own terminal.
- **Coming from sshuttle** ([details](docs/config.md#importing-from-sshuttle)): `subtun import
  sshuttle FILE` turns an options file into a profile, its SSH remote included.

## Build

Needs Go (version in [go.mod](go.mod)), `make` and `git`. No C toolchain: everything builds with
`CGO_ENABLED=0`.

| Target | What it does |
|---|---|
| `make` | `make test` then `make build` |
| `make build` | Linux agents (amd64, arm64) → `internal/agentbin/dist/`, then `build/subtun` for this machine |
| `make test` | unit tests (`make test-race` adds the race detector, needs a C toolchain) |
| `make lint` | `go vet` and a gofmt check (`make fmt` formats) |
| `make release VERSION=v0.1.0 ARGS="--dry-run"` | archives for macOS, Linux and Windows (amd64, arm64) in `build/release/`, without tagging or publishing |
| `make release VERSION=v0.1.0` | the same, then tags and publishes a GitHub release (from an up-to-date `main` only) |
| `make clean` / `make clean-all` | remove the binaries / everything under `build/` |

To run on another machine without building there, take its archive from `build/release/` after a
dry run.

## Planned

- IPv6 through the tunnel; on Linux DNS capture, the kill switch and the IPv6 block (nftables);
  capture on Windows (wintun).
- Deciding per destination inside subtun: names that get their own address and lead to their
  profile wherever they resolve; everything into subtun with the rest leaving directly; failover and
  balancing between profiles.
- Routes that follow network changes; DNS without firewall rules; subtun in the background (a
  daemon); a web UI.

## Documentation

- [Configuration](docs/config.md): the config file and targets, commands, examples, routes and
  excludes, full tunnel, DNS, kill switch, reconnect, IPv6, status and logs, log files, changes while
  running, the terminal UI, safety checks, importing from sshuttle.
- [Design](docs/design.md): measurements, architecture, decisions and open questions.
- [Development](docs/development.md): tests, code layout, the local test setup, and trying a full
  tunnel or the kill switch safely.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).
