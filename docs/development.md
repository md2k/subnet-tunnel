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
| `internal/agent` | agent side: serve smux on stdio, dial on request; UDP flows (`udp.go`: socket reader, queue, stream writer) |
| `internal/tunnel` | laptop side: check the hello, open streams through the agent |
| `internal/transport` | get an agent running in a target (probe, choose binary or Python, start); the labels and idle script of what subtun creates (`owned.go`), a selector's last pick (`picked.go`) |
| `internal/transport/k8s`, `.../docker` | exec into a pod / container; create, reuse and delete subtun's own (`pod.go`, `container.go`); pick an existing one by labels |
| `internal/transport/ssh` | the SSH client: settings from `ssh -G` (`config.go`), keys and the agent (`auth.go`), known_hosts (`hostkey.go`), jump hosts, proxy commands and commands as sessions (`ssh.go`); tests run an SSH server in the test process |
| `internal/socks` | SOCKS5 frontend |
| `internal/control` | the control socket (per process, user-only), its HTTP+JSON API (status, samples, the config's profiles, logs, changes), the client the commands use |
| `internal/tui` | the terminal UI (`subtun tui`, `--tui`; tview): dashboard in two layouts, profile screen, logs, dialogs with dry runs; on a `Source` (the control socket, subtun's API in memory, or a fake); inside subtun, the stop question and the terminal lent to sudo (`Terminal`) |
| `internal/meter` | a tunnel's counters: connections, bytes, 1 s rates, open connections |
| `internal/logring` | the recent log lines in memory (capped by lines and bytes) |
| `internal/logx` | levels per component (the `component` attribute), masking of DNS names and destinations, log files rotated by size and pruned by age and total size |
| `internal/xdg` | subtun's directories, nix style: state (`~/.local/state/subtun`: logs) and run (`$XDG_RUNTIME_DIR/subtun` or `<state>/run`: sockets) |
| `internal/cli` | the commands; planning of routes (automatic excludes), DNS and the kill switch; dry-run output; the engine every run uses, one profile or several (`multi.go`: planning, each profile's tunnel, `runEngine`; `router.go`: a connection's tunnel; `change.go`: changes while running, planned and checked; `status.go`, `statuscmd.go`, `changecmd.go`, `tuicmd.go`, `uptui.go`: status, the control commands and the terminal UI, attached or inside subtun; `target.go`: a target given with `up --k8s` / `--docker` / `--ssh`) |
| `internal/capture` | utun capture setup: helper → utun + routes → netstack; the DNS runtime; the kill switch guard following the local networks; routes and guard changing while running |
| `internal/dns` | DNS engine: match names (`.` leaves local names alone) and pick a tunnel among several, tunnel or fallback, answers outside the routes, UDP/TCP listener, loop-free forwarder |
| `internal/routes` | route planning: excludes by subtraction, cleanup, safety checks |
| `internal/config` | YAML config profiles |
| `internal/importer` | `subtun import sshuttle`: sshuttle options file → profile, insertion into a config file |
| `internal/netinfo` | local interface networks and default gateway (read-only) |
| `internal/netstack` | gVisor stack on a packet device; dials each captured connection through the tunnel, and each UDP flow (`udp.go`); loop guard; hands packets for the utun's own address back |
| `internal/tundev` | utun as a netstack device (macOS) |
| `internal/privhelper` | the root helper (`subtun helper`) and subtun's side of it; a session also takes route changes |
| `internal/platform` | OS driver interfaces used by the helper (`Tun`, `Routes`, `Firewall`, `DNSCache`) |
| `internal/platform/darwin`, `.../fake` | macOS drivers (utun, `/sbin/route`, pf, DNS cache); recording fakes for tests |
| `internal/relay` | bidirectional copy with half-close; the error counts of a UDP flow (`errors.go`) |
| `internal/testutil`, `internal/version` | in-memory connection pairs for tests; the version stamped in at build time |
| `test/dev` | local test setup for both targets |

The netstack tests drive the capture stack from a second gVisor stack over an in-memory wire,
including routing loops built through it (a target that dials onward before accepting, like Docker
Desktop's proxy, and one that accepts first) and the hand-back of packets for the utun's own
address. The CLI tests stub the machine's networks, gateway and search domains, so dry runs don't
depend on where they run, and `internal/config` loads every full YAML example in the docs. The
helper tests cover validation, descriptor passing and the helper's command loop (with recording fake
drivers) over an in-process socket pair. The pf driver is tested against a fake `pfctl` that answers
like a stock macOS. The DNS engine is tested with in-memory packet connections and upstreams; DNS
through both agents runs over in-memory pipes, with the Python agent's sockets swapped for socket
pairs. The terminal UI runs on tcell's simulation screen against a fake control socket: the tests
send keys and read the screen, and check the changes the dialogs make; with `--tui` the engine runs
with a stand-in TUI on its in-memory API. The macOS drivers themselves need root (creating the utun, routes, pf rules) and are tested by
hand, below.

## Local test setup

`test/dev` has a `target` (plain Alpine, where the agent runs) and a `web` service reached through
it. `web.py` serves `GET /bytes/N` (N zero bytes) and discards `PUT`/`POST` bodies, for throughput.

Kubernetes (Docker Desktop, kind, ...):

```sh
kubectl apply -k test/dev
kubectl -n subtun-dev wait --for=condition=Ready pod --all
build/subtun up --k8s -n subtun-dev --create=false --name target --socks 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 http://web.subtun-dev.svc.cluster.local:8080/
kubectl delete namespace subtun-dev
```

Docker:

```sh
docker compose -f test/dev/compose.yaml up -d
build/subtun up --docker --create=false --name subtun-dev-target-1 --socks 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 http://web:8080/
docker compose -f test/dev/compose.yaml down
```

Agent selection: the Kubernetes `locked` pod (non-root, read-only root, `HOME=/`) gets the binary
agent in `/dev/shm/subtun-65534`. The compose `python` profile adds Python targets:

```sh
docker compose -f test/dev/compose.yaml --profile python up -d
build/subtun up --docker --create=false --name subtun-dev-hardened-1 --socks 127.0.0.1:1080      # auto -> Python (no exec-able dir)
build/subtun up --docker --create=false --name subtun-dev-distroless-1 --socks 127.0.0.1:1080    # auto -> Python (no shell)
build/subtun up --docker --create=false --name subtun-dev-py36-1 --agent python --socks 127.0.0.1:1080
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
build/subtun up --k8s -n subtun-dev --create=false --name target $WEB_POD $WEB_SVC   # sudo asks once
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

### Kill switch (needs sudo, run by hand)

```sh
build/subtun -v k8s -n subtun-dev target $WEB_SVC --kill-switch on
sudo pfctl -a com.apple/subtun -s rules; sudo pfctl -a com.apple/subtun -t subtun_guard -T show
pkill -9 -x subtun                                   # as the user: only subtun, not the root helper
curl -m 5 http://$WEB_SVC:8080/                      # refused at once: the block stayed
build/subtun -v k8s -n subtun-dev target $WEB_SVC --kill-switch on   # takes the blocks over (sudo first)
subtun cleanup                                       # or remove them without a session
```

`--kill-switch lockdown` keeps the blocks after Ctrl-C too; with DNS capture, `--kill-switch-dns`
decides whether DNS stays blocked meanwhile. `cat /var/run/subtun/state.json` (as root) shows which
helper holds the rules.


### Reconnect

```sh
build/subtun -v k8s -n subtun-dev target --socks 127.0.0.1:1080 --reconnect-delay 2s
kubectl -n subtun-dev exec target -- pkill -f subtun-agent     # the agent dies: subtun reconnects
curl --socks5-hostname 127.0.0.1:1080 http://web.subtun-dev.svc.cluster.local:8080/
```

The log shows `connection to the agent lost; reconnecting`, `reconnecting attempt=1 ...` and
`reconnected ... after`. Deleting the pod and applying `test/dev` again does the same once the pod is
back; without it, subtun gives up after the attempts. No root is needed for this with SOCKS; with
routes, `netstat -rn -f inet | grep utun` shows the routes staying throughout.

### Several profiles

Without root, through SOCKS: one profile per target, plus one that can't connect.

```sh
cat > build/multi.yaml <<'EOF'
profiles:
  kube:
    target: {k8s: {context: docker-desktop, namespace: subtun-dev, create: false, name: target}}
    socks: 127.0.0.1:17080
  dock:
    target: {docker: {create: false, name: subtun-dev-target-1}}
    socks: 127.0.0.1:17081
  ghost:
    target: {k8s: {context: docker-desktop, namespace: subtun-dev, create: false, name: no-such-pod}}
    socks: 127.0.0.1:17082
    reconnect: {attempts: 1}
EOF
build/subtun --config build/multi.yaml up --profile kube,dock,ghost
curl --socks5-hostname 127.0.0.1:17080 http://web.subtun-dev.svc.cluster.local:8080/  # the pod's
curl --socks5-hostname 127.0.0.1:17081 http://web:8080/                               # the container's
```

Log lines carry `tunnel=<profile>`. `ghost` logs `gave up` and the others carry on; with only
profiles that can't connect, subtun exits with `every profile gave up`. With routes (sudo),
`netstat -rn -f inet | grep utun` shows a profile's routes appear when its tunnel is up and go
when it gives up (unless it has a kill switch); `--dry-run` shows which tunnel each route goes to.

### Pods and containers subtun creates

Without root, through SOCKS, against the local cluster and Docker. The node of Docker Desktop's
cluster may not pull from Docker Hub by itself behind a proxy: `docker pull busybox:1.37` on the
host first, or give an image it has (`--image alpine:3.20`).

```sh
build/subtun up --k8s --context docker-desktop -n subtun-dev --socks 127.0.0.1:18086
kubectl --context docker-desktop -n subtun-dev get pods -l app.kubernetes.io/managed-by=subtun
curl --socks5-hostname 127.0.0.1:18086 http://web.subtun-dev.svc.cluster.local:8080/
build/subtun up --docker --network subtun-dev_default --socks 127.0.0.1:18087
curl --socks5-hostname 127.0.0.1:18087 http://web:8080/
```

`kubectl exec <pod> -- pkill -f subtun-agent` reconnects to the same pod; deleting the pod makes
subtun create another; Ctrl-C deletes it; after `kill -9` the pod stays (it exits after 5 idle
minutes) and the next start deletes it. `-l app=web` picks the `web` Deployment's pod, and
`kubectl delete pod -l app=web` makes the reconnect pick its replacement.

### SSH targets

The compose `ssh` profile runs two OpenSSH servers (linuxserver/openssh-server) that take a
throwaway key: `sshd` published on 127.0.0.1:2222 (with TCP forwarding, so it's also a jump host)
and `sshd-inner` on the compose network only. `SUBTUN_SSH_CONFIG` hands subtun's `ssh -G` another
config file (`ssh -F`), so the test keeps its host keys out of your own known_hosts.

```sh
mkdir -p build/ssh-test && ssh-keygen -t ed25519 -N "" -f build/ssh-test/id_ed25519
printf 'Host *\n  UserKnownHostsFile %s/build/ssh-test/known_hosts\n  IdentityFile %s/build/ssh-test/id_ed25519\n  IdentitiesOnly yes\n' "$PWD" "$PWD" > build/ssh-test/config
docker compose -f test/dev/compose.yaml --profile ssh up -d
export SUBTUN_SSH_CONFIG=build/ssh-test/config
build/subtun up --ssh subtun@127.0.0.1:2222 --socks 127.0.0.1:18090                            # asks about the host key
curl --socks5-hostname 127.0.0.1:18090 http://web:8080/
build/subtun up --ssh subtun@sshd-inner:2222 -J subtun@127.0.0.1:2222 --socks 127.0.0.1:18091  # through the jump host
docker compose -f test/dev/compose.yaml --profile ssh down
```

Without a terminal the unknown host key is refused (run it from a script to see the hint);
`docker exec subtun-dev-sshd-1 pkill -f subtun-agent` reconnects without asking again; `docker
restart subtun-dev-sshd-1` drops the connection and reconnect brings it back. With `--tui` the
terminal UI steps aside for the host key question.

### The terminal UI inside subtun

`--tui` runs the TUI in subtun's own terminal; through SOCKS it needs no root. Watch the log lines
in it, stop `ghost` or `dock` with `s` (changes work whatever `control` says), then `q`: it asks,
shows the stop, and prints the stop's log lines when it closes.

```sh
build/subtun --config build/multi.yaml up --profile kube,dock --tui
```

With routes, by hand on a machine where sudo may run: `subtun up PROFILE --tui` with no sudo
ticket steps aside for sudo's prompt (or Touch ID) and comes back once the helper runs; with a
ticket (`sudo -v` just before) it doesn't step aside.

### Loop guard (needs sudo, run by hand)

Docker Desktop's pods reach the internet through the Mac, so routing an internet address through one
makes a loop, which subtun must cut:

```sh
build/subtun -v k8s -n subtun-dev target 1.1.1.1 --max-duration 2m
curl -m 20 -s -o /dev/null -w '%{http_code} %{time_total}\n' https://1.1.1.1/   # fails within seconds
```

The log shows the start warning (`the target seems to run on this machine ...`) and
`refusing connections to this destination for a while: too many at once, likely a routing loop`,
at most once a minute per destination; for 10 s, retries are refused at once. Everything not
routed works throughout. A full tunnel through Docker Desktop does the same for every internet
address, your own remote session's included: only ever with `--max-duration`, and as described in
[Full tunnel and kill switch, safely](#full-tunnel-and-kill-switch-safely).

### A way back: `--max-duration`

The hidden `--max-duration DURATION` flag makes subtun stop by itself, the same way as on Ctrl-C, once
the time is up. The clock starts with subtun, so the sudo prompt and connecting count too. Use it for
any run that may cut your own network, like a full tunnel or the kill switch:

```sh
build/subtun -v k8s -n subtun-dev target 0.0.0.0/1 128.0.0.0/1 --max-duration 2m
```

If stopping hangs, subtun exits 20 seconds later anyway (exit code 3). macOS then removes the utun
and its routes, and the root helper removes its firewall rules, except a kill switch's blocks, which
stay as they would after a crash (`subtun cleanup` removes them). With `--kill-switch lockdown` the
blocks stay after `--max-duration` too, as after Ctrl-C.

## Full tunnel and kill switch, safely

A full tunnel carries all of the machine's traffic, including the remote shell or screen-sharing
session you may be watching the test from, and a kill switch blocks traffic on purpose when the
tunnel goes away. So when trying either:

- **Use a target outside this machine.** A local Docker Desktop, kind or minikube pod loops a full
  tunnel back ([Routing loops](config.md#routing-loops)). To check the loop guard, route one internet
  address through a local pod instead ([above](#loop-guard-needs-sudo-run-by-hand)).
- **Always set `--max-duration`,** so subtun stops by itself even when you can't reach the machine
  any more ([below](#a-way-back---max-duration)).
- **Script the checks.** Start subtun in the background, run the checks from the same script, stop
  subtun and run `subtun cleanup`. Nothing then needs the network while the tunnel is up, and a
  remote session only has to wait for the script:

  ```sh
  sudo -v                                              # the helper's sudo reuses this
  build/subtun -v k8s --context remote -n tools egress 0.0.0.0/1 128.0.0.0/1 \
    --dns-domain . --dns-domain cluster.local --kill-switch on --max-duration 3m > build/full.log 2>&1 &
  pid=$!
  until grep -q msg=capturing build/full.log || ! kill -0 $pid 2>/dev/null; do sleep 1; done
  curl -s -m 10 https://api.ipify.org; echo            # the pod's public address, not yours
  route -n get default | grep interface                # the default route is untouched (en0)
  dig +short example.com                               # DNS, through the tunnel
  sudo -n pfctl -a com.apple/subtun -s rules           # the kill switch's rules
  kill -TERM $pid; wait $pid
  build/subtun cleanup                                 # "nothing to clean up" after a clean stop
  ```
- **Go step by step:** `--dry-run`, split routes, a full tunnel without the kill switch, then
  `--kill-switch on`, and `lockdown` last.
- **Keep a second way in** when the machine isn't in front of you: SSH or Screen Sharing from
  another machine on the LAN. The LAN stays outside the tunnel and isn't blocked by the kill switch.

If the network is gone, in this order:
1. Wait: every run ends within its `--max-duration` plus 20 s.
2. Ctrl-C, or `pkill -TERM -x subtun`. `netstat -rn -f inet | grep utun` must show no `0/1` or
   `128.0/1` rows.
3. `subtun cleanup` removes a kill switch's blocks, and rules a killed helper left.
4. If Wi-Fi was switched off, switch it on.
5. Reboot: the utun, the routes and pf's rules all live in memory.

What to look at while it runs:
- routes: `netstat -rn -f inet | grep utun`; `route -n get <gateway>` stays on `en0`;
- pf: `sudo pfctl -a com.apple/subtun -s rules` and `-s nat`; `-t subtun_guard -T show` lists the
  guarded prefixes, and `-t subtun_guard -T test ADDR` says whether an address is blocked;
- the log: `kill switch on mode=... guarded_prefixes=N`, `local networks changed; kill switch
  follows`, and the helper's `DNS cache flushed`.

**A network change without a second network.** Give `en0` a second address in a documentation range
inside an unused route, during a kill switch session, and the guard follows it within about 5 s:

```sh
build/subtun -v k8s -n tools egress 198.51.0.0/16 --kill-switch on --max-duration 2m &
sudo ifconfig en0 alias 198.51.100.1 netmask 255.255.255.0         # a "new LAN" inside the route
sleep 8; sudo pfctl -a com.apple/subtun -t subtun_guard -T test 198.51.100.5   # 0/1 addresses match
sudo ifconfig en0 -alias 198.51.100.1
sleep 8; sudo pfctl -a com.apple/subtun -t subtun_guard -T test 198.51.100.5   # 1/1: blocked again
```
