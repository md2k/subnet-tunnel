# subnet-tunnel (`subtun`)

Route chosen subnets and DNS domains from your laptop through a remote host, Kubernetes pod or
Docker container, as if you were on that network. A single static Go binary: no Python, no
runtime dependencies, nothing to install on the far side.

Inspired by [sshuttle](https://github.com/sshuttle/sshuttle). Built because on macOS sshuttle's
pf-based capture caps upload at a few MB/s, while a utun interface with a userspace TCP/IP stack
reached ~170 MB/s end to end in the same test (see [docs/design.md](docs/design.md)).

> **Status:** early development. Kubernetes and Docker targets, transparent capture of CIDRs or a
> full tunnel on macOS (utun + gVisor), split DNS, a kill switch and a SOCKS5 proxy.

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
| `make lint` | `go vet` and a gofmt check (`make fmt` formats) |
| `make release VERSION=v0.1.0 ARGS="--dry-run"` | builds archives for macOS, Linux and Windows (amd64, arm64) in `build/release/`, without tagging or publishing |
| `make release VERSION=v0.1.0` | the same, then tags and publishes a GitHub release (from an up-to-date `main` only) |
| `make clean` / `make clean-all` | remove the binaries / everything under `build/` |

To run on another machine without building there, take its archive from `build/release/` after a
dry run.

## Use

```sh
# Capture CIDRs (or single IPs) through a pod subtun creates in team-a (and deletes on stop):
# every program on this machine reaches them directly (macOS)
build/subtun up --k8s -n team-a 10.96.0.0/12 10.244.0.0/16
curl http://10.96.12.34:8080/

# SOCKS5 proxy, for example for a browser; hostnames resolve inside the target. Here an
# existing pod: subtun only starts its agent in it
build/subtun up --k8s -n team-a --create=false --name debug-pod --socks 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 http://my-svc.team-a.svc.cluster.local

# Both at once, and the same with a container subtun creates on a Docker network
build/subtun up --docker --network my-app_default 172.20.0.0/16 --socks 127.0.0.1:1080

# Split DNS: names under cluster.local resolve inside the pod, everything else as before
build/subtun up --k8s -n team-a 10.96.0.0/12 10.244.0.0/16 --dns-domain cluster.local
curl http://my-svc.team-a.svc.cluster.local:8080/

# Everything through a pod in a remote cluster, every name resolved there, and nothing leaking
# if the tunnel goes away
build/subtun up --k8s --context remote -n tools 0.0.0.0/1 128.0.0.0/1 \
  --dns-domain . --dns-domain cluster.local --kill-switch on

build/subtun up --k8s -n team-a 10.0.0.0/8 --dry-run   # what would happen, without root
build/subtun cleanup                                    # remove blocks a kill switch left
```

subtun connects with your kubeconfig or Docker context, starts a small agent in the target over exec
and opens connections from inside the target. No `kubectl port-forward`, no sshd, no second
terminal.

**Capture and root.** subtun runs as your user. With CIDRs, sudo asks for your password once: a
short-lived helper creates a utun interface (MTU 9000), adds routes for your CIDRs, hands the
interface to subtun and exits. Traffic is only ever handled by the subtun process running as you.
The routes live and die with the interface: when subtun exits, crashes or is killed, macOS removes
both, so nothing is left behind. To change CIDRs, restart subtun. With split DNS, a kill switch or
IPv6 blocking, the helper stays up instead, to remove its pf rules again when subtun stops. See
[Privileges](docs/design.md#privileges) for how this works.

Two agents speak the same protocol; `--agent auto` (the default) picks the first that can run:

| `--agent` | Target needs | Writes to the target |
|---|---|---|
| `binary` | Linux amd64/arm64, `sh` with basic tools (busybox is enough), a writable directory that allows exec | one cached ~3.5 MB binary in a private directory: `~/.cache/subtun`, else `/tmp/subtun-<uid>`, `/var/tmp/subtun-<uid>`, `/dev/shm/subtun-<uid>`, or `--agent-dir` |
| `python` | Python 3.6+ (no shell needed) | nothing: the source is sent over exec and run from memory, like sshuttle |

Both reach about the same speed in our tests. Images with neither a shell nor Python (distroless
static, scratch) are not supported yet.

**Split DNS.** With `--dns-domain` (suffixes) or `--dns-pattern` (regular expressions), subtun
answers the queries your Mac sends to its DNS servers: matching names are resolved by the target's
own resolver through the tunnel, the rest by your normal resolver. Like sshuttle's `--dns` with
domain patterns, for any number of domains; `--dns-domain .` sends every name except local ones.
See [DNS](docs/config.md#dns).

**Kill switch.** `--kill-switch on` keeps traffic for your routes from leaving any other way when
the tunnel is gone (crash, lost pod): the blocks stay until the next run or `subtun cleanup`;
`lockdown` keeps them even after Ctrl-C. The blocks follow your networks, so another Wi-Fi's LAN
stays reachable. See [Kill switch](docs/config.md#kill-switch).

**Full tunnel.** Routing `0.0.0.0/1 128.0.0.0/1` sends everything through the target; your LAN,
multicast and link-local stay local, and IPv6, which subtun doesn't carry yet, is blocked. The target
has to run outside this machine: a local Docker Desktop pod would loop your traffic back (subtun
warns and cuts such loops). See [Full tunnel](docs/config.md#full-tunnel).

**Reconnect.** When the connection to the target drops, subtun tries again (10 times by default,
waiting longer each time) while routes, firewall rules and the proxy stay in place. See
[Reconnect](docs/config.md#reconnect).

**Excludes and profiles.** `-x/--exclude` keeps addresses out of the tunnel; the most specific rule
wins, like sshuttle. `--dry-run` prints the routes subtun would install. Settings can live in named
profiles in `~/.config/subtun/config.yaml`:

```yaml
profiles:
  dev-cluster:
    target: {k8s: {context: dev, namespace: tools}}
    routes: [10.0.0.0/8, 172.16.0.0/12]
    exclude: [10.1.0.0/16]
    socks: 127.0.0.1:1080
    dns: {domains: [cluster.local, company.com]}
    killSwitch: {mode: on}
```

```sh
build/subtun up dev-cluster            # flags still override, extra CIDRs and -x are added
```

**Several remotes at once.** `subtun up --profile work,dev` runs several profiles in one process:
each connection and DNS name goes to the profile whose route or domain matches most specifically,
and each profile reconnects, or gives up, on its own. See
[Several profiles at once](docs/config.md#several-profiles-at-once).

**Status.** `subtun status` shows what every running subtun is doing: each tunnel's state, routes,
DNS names, connections and traffic; `subtun logs -f` follows its log. Each run also writes a JSON
log file (rotated, kept 3 days), with levels per component (`--log-level info,dns=debug`) and
optional masking of names and addresses. See [Status and logs](docs/config.md#status-and-logs) and
[Log files](docs/config.md#log-files).

**Changes while running.** Started with `--control full`, a subtun takes `subtun route add|del`,
`subtun dns add|del` and `subtun profile stop|start|reconnect` without a restart. See
[Changes while running](docs/config.md#changes-while-running).

**Terminal UI.** `subtun tui` attaches to a running subtun: its profiles, traffic and log lines, in
two layouts. With `--control full` it also stops, starts and reconnects profiles, edits their routes
and DNS names and adds profiles from the config file, each change after its dry run. Or run subtun
with it in the same terminal: `subtun up work --tui` (`q` stops subtun, after asking). See
[Terminal UI](docs/config.md#terminal-ui).

See [Configuration](docs/config.md). Coming from sshuttle? `subtun import sshuttle FILE --name NAME`
turns an sshuttle options file into a profile ([details](docs/config.md#importing-from-sshuttle)).

## Planned

- Routes that follow network changes, and DNS answers outside the routes routed into the tunnel;
  subtun in the background (a daemon); a web UI.
- SSH transport to any host.
- DNS without firewall rules: subtun as the system resolver, or only for the listed domains.
- UDP and IPv6 through the tunnel; capture on Linux (TUN) and Windows (wintun).

## Documentation

- [Configuration](docs/config.md): commands, profiles and defaults, several profiles at once,
  examples, routes and excludes, full tunnel, split DNS, kill switch, reconnect, IPv6, status and
  logs, log files, changes while running, the terminal UI, safety checks, importing from sshuttle.
- [Design](docs/design.md): measurements, architecture and open questions.
- [Development](docs/development.md): tests, code layout, the local test setup, and trying a full
  tunnel or the kill switch safely.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).
