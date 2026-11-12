# Development

## Build and test

Make targets are listed in the [README](../README.md#build).

`make agents` (part of `make build`) cross-compiles `cmd/subtun-agent` for linux/amd64 and linux/arm64 into
`internal/agentbin/dist/`, where `go:embed` picks them up. A plain `go build ./cmd/subtun` works
without them, but then subtun has no agent to upload; pass `--agent-file` (hidden flag) with a
Linux build of `cmd/subtun-agent` instead.

Unit tests use in-memory connections and stub dialers. They open no network sockets. The Python
agent tests in `internal/agentpy` run the real `agent.py` with the local `python3` over pipes, with
dialing replaced by in-process socket pairs (`testdata/fakenet.py`), against the Go tunnel client;
they skip when there is no Python 3.6+. Older interpreters are covered by the `py36` compose target
below.

## Releases

`make release VERSION=vX.Y.Z` runs [scripts/release.sh](../scripts/release.sh): preflight (clean
tree, on `main`, in sync with origin, tag and release free), Linux agents, then `subtun` for
darwin/linux/windows × amd64/arm64 with `-trimpath -s -w` and the version stamped in, `.tar.gz` /
`.zip` archives plus `checksums.txt` in `build/release/`, then the tag and `gh release create`.
Everything is built before anything is pushed, so a failed build leaves no tag behind.
`ARGS="--dry-run"` stops after the build and skips the git/gh checks, so it works from any branch.
`ARGS="--notes-file notes.md"` replaces the generated release notes.

gh doesn't follow git's per-directory identity. If the active gh account can't see the repo, the
script stops at preflight; run it with `GH_TOKEN=$(gh auth token -u <user>)`.

## Layout

| Path | What |
|---|---|
| `cmd/subtun` | the CLI |
| `cmd/subtun-agent` | the remote agent (Linux, static) |
| `internal/agentbin` | embedded Linux agent binaries |
| `internal/agentpy` | the Python agent (`agent.py`) and its loader |
| `internal/proto` | hello line, per-stream request/response, smux settings |
| `internal/agent` | agent side: serve smux on stdio, dial on request |
| `internal/tunnel` | laptop side: check the hello, open streams through the agent |
| `internal/transport` | get an agent running in a target (probe, choose binary or Python, start) |
| `internal/transport/k8s`, `.../docker` | exec into a pod / container |
| `internal/socks` | SOCKS5 frontend |
| `internal/capture` | utun capture setup: helper → utun + routes → netstack |
| `internal/dns` | DNS engine: match names, tunnel or fallback, UDP/TCP listener, loop-free forwarder |
| `internal/routes` | route planning: excludes by subtraction, cleanup, safety checks |
| `internal/config` | YAML config profiles |
| `internal/netinfo` | local interface networks and default gateway (read-only) |
| `internal/netstack` | gVisor stack on a packet device; dials each captured connection through the tunnel |
| `internal/tundev` | utun as a netstack device (macOS) |
| `internal/privhelper` | the root helper (`subtun helper`) and subtun's side of it |
| `internal/platform` | OS driver interfaces used by the helper (`Tun`, `Routes`) |
| `internal/platform/darwin`, `.../fake` | macOS drivers (utun, `/sbin/route`); recording fakes for tests |
| `internal/relay` | bidirectional copy with half-close |
| `test/dev` | local test setup for both targets |

The netstack tests drive the capture stack from a second gVisor stack over an in-memory wire. The
helper tests cover validation, descriptor passing and the helper's command loop (with recording fake
drivers) over an in-process socket pair. The pf driver is tested against a fake `pfctl` that answers
like a stock macOS. The DNS engine is tested with in-memory packet connections and upstreams; DNS
through both agents runs over in-memory pipes, with the Python agent's sockets swapped for socket
pairs. The macOS drivers themselves need root (creating the utun, routes, pf rules) and are tested by
hand, below.

## Local test setup

`test/dev` has a `target` (plain Alpine, where the agent runs) and a `web` service reached through
it. `web.py` serves `GET /bytes/N` (N zero bytes) and discards `PUT`/`POST` bodies, for throughput.

Kubernetes (Docker Desktop, kind, ...):

```sh
kubectl apply -k test/dev
kubectl -n subtun-dev wait --for=condition=Ready pod --all
build/subtun k8s -n subtun-dev target --socks 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 http://web.subtun-dev.svc.cluster.local:8080/
kubectl delete namespace subtun-dev
```

Docker:

```sh
docker compose -f test/dev/compose.yaml up -d
build/subtun docker subtun-dev-target-1 --socks 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 http://web:8080/
docker compose -f test/dev/compose.yaml down
```

Agent selection: the Kubernetes `locked` pod (non-root, read-only root, `HOME=/`) gets the binary
agent in `/dev/shm/subtun-65534`. The compose `python` profile adds Python targets:

```sh
docker compose -f test/dev/compose.yaml --profile python up -d
build/subtun docker subtun-dev-hardened-1 --socks 127.0.0.1:1080      # auto -> Python (no exec-able dir)
build/subtun docker subtun-dev-distroless-1 --socks 127.0.0.1:1080    # auto -> Python (no shell)
build/subtun docker subtun-dev-py36-1 --agent python --socks 127.0.0.1:1080
docker compose -f test/dev/compose.yaml --profile python down
```

If the Kubernetes node can't pull images (for example behind a TLS-inspecting proxy), pull them
with `docker pull alpine:3.20 python:3.12-alpine` first; Docker Desktop's node gets them through
its registry mirror.

Throughput, through the proxy:

```sh
curl --socks5-hostname 127.0.0.1:1080 -o /dev/null -w '%{speed_download}\n' http://web:8080/bytes/524288000
dd if=/dev/zero of=build/bench.dat bs=1048576 count=500
curl --socks5-hostname 127.0.0.1:1080 -o /dev/null -T build/bench.dat -w '%{speed_upload}\n' http://web:8080/up
```

### utun capture (needs sudo, run by hand)

Docker Desktop's pod and service IPs aren't reachable from macOS, which makes them a good test.
Use single IPs or narrow ranges: wide 10.x ranges can overlap corporate networks your VPN routes.

```sh
WEB_POD=$(kubectl -n subtun-dev get pod -l app=web -o jsonpath='{.items[0].status.podIP}')
WEB_SVC=$(kubectl -n subtun-dev get svc web -o jsonpath='{.spec.clusterIP}')
build/subtun k8s -n subtun-dev target $WEB_POD $WEB_SVC        # sudo asks once
curl http://$WEB_SVC:8080/                                     # in another terminal
netstat -rn -f inet | grep utun                                # routes on the utun
```

After Ctrl-C, and also after `kill -9` of subtun, `ifconfig | grep utun` and
`netstat -rn -f inet | grep utun` must no longer show subtun's interface or routes.

Tips:
- sudo caches your password (or Touch ID) for a few minutes. To test the prompt itself (Ctrl-C at
  the prompt, wrong password), start with `sudo -k && build/subtun …`.
- To keep a log, use `build/subtun … 2>&1 | tee -i build/run.log`: without `-i`, Ctrl-C also kills
  `tee` and subtun's last lines (shutdown) are lost.

### DNS without root

The hidden `--dns-listen ADDR` flag answers DNS on a local address instead of capturing it, so the
DNS path through the agent can be tested with `dig` and no sudo. Pick a free port; 5353 belongs to
macOS's mDNS responder.

```sh
build/subtun -v k8s -n subtun-dev target --dns-listen 127.0.0.1:15353 --dns-domain cluster.local
dig @127.0.0.1 -p 15353 +short web.subtun-dev.svc.cluster.local      # the service's ClusterIP
dig @127.0.0.1 -p 15353 +tcp web.subtun-dev.svc.cluster.local SRV
build/subtun -v docker subtun-dev-py36-1 --agent python --dns-listen 127.0.0.1:15353 --dns-domain .
dig @127.0.0.1 -p 15353 +short web                                   # Docker's embedded DNS
```

### DNS capture (needs sudo, run by hand)

```sh
build/subtun -v k8s -n subtun-dev target $WEB_SVC --dns-domain cluster.local
dscacheutil -q host -a name web.subtun-dev.svc.cluster.local   # through the system resolver
curl http://web.subtun-dev.svc.cluster.local:8080/
sudo pfctl -a com.apple/subtun -s nat; sudo pfctl -a com.apple/subtun -s rules   # subtun's rules
sudo pfctl -a com.apple/subtun -t subtun_dns -T show                              # captured servers
```

`-s nat` and `-s rules` print the rules in pf's expanded form (one line per protocol, `port = 53`) and
don't show the table; before the first run the anchor doesn't exist yet and pfctl says
`DIOCGETRULES: Invalid argument`.

After Ctrl-C, `kill -9` of subtun, or closing the terminal, both `pfctl` commands must print
nothing, and names outside your domains must resolve as before throughout.

