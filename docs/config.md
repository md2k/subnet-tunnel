# Configuration

Everything can be given on the command line, or kept in named profiles in a YAML file and started
with `subtun up NAME`.

## File

Location: `--config FILE`, else `$SUBTUN_CONFIG`, else `$XDG_CONFIG_HOME/subtun/config.yaml`, else
`~/.config/subtun/config.yaml`. Parsing is strict: an unknown key is an error, so a typo can't
silently drop a setting. Besides `defaults:` and `profiles:`, the top level takes `control:` (see
[Status and logs](#status-and-logs)), `log:` (see [Log files](#log-files)) and `tui:` (see
[Terminal UI](#terminal-ui)).

```yaml
defaults:                          # optional: any profile key except target, for every profile
  exclude: [192.168.1.0/24]
  killSwitch: {mode: on}

profiles:
  dev-cluster:                     # a lowercase letter or digit, then also '.', '_', '-'
    target:                        # exactly one of k8s / docker / ssh: see Targets below
      k8s:                         # a pod subtun creates, and deletes on stop
        kubeconfig: ~/.kube/dev    # default: $KUBECONFIG or ~/.kube/config
        context: dev               # default: the kubeconfig's current context
        namespace: tools           # default: the context's namespace
        name: subtun-dev           # default: subtun-<profile>-<random>
        image: busybox:1.37        # default; it needs a shell
        resources:                 # optional
          requests: {cpu: 50m, memory: 64Mi}
          limits: {memory: 512Mi}
    routes:                        # captured through the utun (CIDRs or single IPs)
      - 10.0.0.0/8
      - 172.16.0.0/12
    exclude:                       # never captured (most specific rule wins, see below)
      - 10.1.0.0/16
    socks: 127.0.0.1:1080          # optional SOCKS5 proxy
    agent: auto                    # auto | binary | python
    agentDir: /work                # binary agent location in the target (default: automatic)
    tun:
      address: 198.18.249.1        # subtun's own utun address (default)
      mtu: 9000                    # default
    dns:                           # split DNS, see below
      domains: [svc.cluster.local, company.com]
      patterns: ['^db-[0-9]+\.prod\.']
      servers: auto                # default
      fallback: system             # default
      capture: firewall            # default; off disables DNS capture
      unrouted: warn               # default: tunnel answers outside the routes, see below
    killSwitch:                    # see below
      mode: off                    # off (default) | on | lockdown
      dns: block                   # block (default) | allow
    blockIPv6: auto                # auto (default: in a full tunnel) | true | false
    reconnect:                     # when the connection to the agent is lost, see below
      attempts: 10                 # default; 0: exit instead
      delay: 1s                    # default: the first wait, doubling after each attempt
      maxDelay: 1m                 # default: the longest wait

  toolbox:
    target:
      k8s:                         # an existing pod: subtun only starts its agent in it
        context: dev
        namespace: tools
        create: false
        name: toolbox-0            # or selector: app=toolbox (picked at each connect)
        container: shell           # default: kubectl's default container
    socks: 127.0.0.1:1082

  local-app:
    target:
      docker:                      # a container subtun creates, and removes on stop
        host: unix:///var/run/docker.sock   # default: $DOCKER_HOST, then the docker context
        context: desktop-linux               # default: $DOCKER_CONTEXT, then the current context
        network: app_default                 # default: the default bridge
        image: busybox:1.37                  # default
        name: subtun-local-app               # default: subtun-<profile>-<random>
        resources: {limits: {cpu: "1", memory: 512Mi}}   # limits only
    socks: 127.0.0.1:1081

  web:
    target:
      docker: {create: false, selector: com.docker.compose.service=web}   # or name: app-web-1
    socks: 127.0.0.1:1083

  office:
    target:
      ssh:                         # a host over SSH: the agent runs there as you
        host: me@gw.example.com:22 # [user@]host[:port], or a Host from ~/.ssh/config
        identity: ~/.ssh/work      # optional: a key tried first
        jump: me@bastion.example.com   # optional: ProxyJump, comma-separated hops
    routes: [10.40.0.0/16]
```

A profile needs `routes`, `socks` or both (its own or from `defaults`).

### Targets

A target is where the agent runs: a Kubernetes pod, a Docker container, or a host over SSH.

- **Created** (the default): subtun creates the pod or container, starts its agent in it, creates
  it again if it goes (deleted, evicted, its node gone), and deletes it when the profile stops.
  Its image (`image`, default `busybox:1.37`; it needs a shell for the agent's upload) has to be
  one the cluster or daemon can pull: a cluster that only takes images from its own registry needs
  its mirror here. The pod runs as an unprivileged user with nothing mounted but a scratch
  directory, so it fits a namespace's restricted pod security level. Creating pods needs the
  permission to create, get, list and delete pods in the namespace, besides exec. A container runs
  the same way on `network` (default: the default bridge), with `resources.limits` only. A pod or
  container left behind (subtun killed) exits after 5 minutes without an agent, and the next start
  removes it; subtun only touches what it created for you on this machine (their labels say so).
  Unset requests are small (10m CPU, 32Mi), capped at the limits given. The kube context and
  namespace, or the Docker daemon, are those of the first connect: switching contexts while subtun
  runs doesn't move it.
- **Existing** (`create: false`): subtun only starts its agent in it, by exact `name`, or by
  `selector`: labels (kubectl's syntax for Kubernetes; `key=value`, comma-separated, for Docker),
  where a running, ready one is picked at each connect: the one used before while it still is,
  else the newest. So a reconnect finds a pod that replaced one that went, and several pods with
  the same labels act as spares. `selector` alone means an existing one (`create: false` can be
  left out).
- **SSH** (`ssh`): a host subtun logs in to, as sshuttle does; the agent runs there as the login
  user, and nothing needs to be installed but sshd and a POSIX `sh` (the binary agent on Linux,
  the Python agent on other systems). subtun's own client connects the way `ssh` would:
  `~/.ssh/config` as OpenSSH reads it (`ssh -G`: Host, Match and Include, HostName, User, Port,
  IdentityFile, ProxyJump, ProxyCommand, known_hosts files), under `user`, `port`, `identity` and
  `jump` set here. Logins are by key only: the SSH agent's keys and key files (an encrypted key
  asks for its passphrase once per run, and only when the server takes it), certificates too; no
  passwords. A host key not yet in known_hosts is asked about on the terminal, as `ssh` asks, and
  saved (`StrictHostKeyChecking yes` refuses it instead, `accept-new` saves it without asking;
  without a terminal subtun refuses and says how to accept it with `ssh`). A changed key is always
  refused. With `--tui` the terminal UI steps aside for these questions. Not supported: Kerberos
  (GSSAPI) and ControlMaster.
- A target can't go in `defaults`: each profile names its own, even when two repeat it.

**Agents.** subtun starts a small agent in the target and opens connections from there. Two agents
speak the same protocol; `agent: auto` (`--agent`, the default) picks the first that can run:

| `agent` | Target needs | Writes to the target |
|---|---|---|
| `binary` | Linux amd64/arm64, `sh` with basic tools (busybox is enough), a writable directory that allows exec | one cached ~3.5 MB binary in a private directory: `~/.cache/subtun`, else `/tmp/subtun-<uid>`, `/var/tmp/subtun-<uid>`, `/dev/shm/subtun-<uid>`, or `agentDir` |
| `python` | Python 3.6+ (no shell needed) | nothing: the source is sent over and run from memory, like sshuttle |

Both reach about the same speed in our tests. Targets with neither a shell nor Python (distroless
static, scratch) are not supported yet; a pod or container subtun creates runs busybox, so it's
fine.

**Defaults.** Settings under `defaults` apply to every profile. A profile's own value wins; lists
(`routes`, `exclude`, `dns.domains`, `dns.patterns`) add up, so a home-LAN exclude in `defaults`
applies everywhere. Settings that need routes (DNS capture, the kill switch, IPv6 blocking) are
ignored, with a warning, in a profile without routes, so a kill switch in `defaults` doesn't break
a SOCKS-only profile. YAML treats bare `on`, `off`, `yes` and `no` as booleans; subtun reads them as
the words you meant (`mode: off`, `capture: off` work).

## Commands

| Command | What it does |
|---|---|
| `subtun up [PROFILE] [CIDR...]` | run a profile from the config file; without a name, list them |
| `subtun up --k8s [CIDR...]` | tunnel through a pod given here: one subtun creates (`--image`, `--name`, `--requests`, `--limits`), or an existing one (`--create=false` with `--name` or `-l`); `-n`, `-c`, `--context`, `--kubeconfig` |
| `subtun up --docker [CIDR...]` | the same through a Docker container (`--network`, `-H`, `--context`) |
| `subtun up --ssh [USER@]HOST[:PORT] [CIDR...]` | through a host over SSH (`-i KEY`, `-J JUMP`; the rest from `~/.ssh/config`) |
| `subtun up --profile A,B` | run several profiles at once ([below](#several-profiles-at-once)) |
| `subtun status` | what every running subtun is doing ([below](#status-and-logs)) |
| `subtun logs [-f]` | a running subtun's recent log lines |
| `subtun tui` | watch and change a running subtun in a terminal UI ([below](#terminal-ui)); `--tui` on `up` runs subtun with it in the same terminal |
| `subtun route add\|del CIDR...` | change a running subtun's routes ([below](#changes-while-running)) |
| `subtun dns add\|del DOMAIN...` | change a running subtun's DNS names |
| `subtun profile stop\|start\|reconnect [NAME]` | stop, start or reconnect one of its profiles |
| `subtun log level [SPEC]` | show or change a running subtun's log levels |
| `subtun cleanup` | remove firewall rules an earlier session left (a kill switch's blocks), without starting one |
| `subtun import sshuttle FILE` | turn an sshuttle options file into a profile ([below](#importing-from-sshuttle)) |
| `subtun version` | print the version |
| `subtun completion bash\|zsh\|fish\|powershell` | a shell completion script |

Global flags: `--config FILE`, `-v` (debug logging, in subtun and in the agent). Hidden flags for
testing (`--max-duration`, `--dns-listen`, `--agent-file`) are described in
[Development](development.md).

## Command line and profiles together

```sh
subtun up                                  # list profiles
subtun up dev-cluster                      # run it
subtun up dev-cluster --dry-run            # show the planned routes, DNS and kill switch, and exit
subtun up dev-cluster 10.50.0.0/16 -x 10.50.1.0/24 --socks 127.0.0.1:1082
```

Flags given on the command line override the profile's (and defaults') values (`--socks`,
`--agent`, `--agent-dir`, `--tun-addr`, `--mtu`, `--dns-capture`, `--dns-servers`, `--dns-fallback`,
`--dns-unrouted`, `--kill-switch`, `--kill-switch-dns`, `--block-ipv6`, `--reconnect-attempts`,
`--reconnect-delay`, `--reconnect-max-delay`). CIDRs, `-x/--exclude`,
`--dns-domain` and `--dns-pattern` given on the command line are **added** to the profile's. Without
a profile, the same flags work with a target given on the command line (`--k8s`, `--docker`,
`--ssh`).

## Several profiles at once

```sh
subtun up --profile work,dev               # or: subtun up work --profile dev
subtun up --profile work --profile dev --dry-run
```

Each profile connects to its own target, and they share one utun: a connection goes to the profile
whose configured route matches its destination most specifically (a profile's excludes only take
addresses out of its own routes), a DNS name to the profile with the longest matching domain (then
the first matching pattern, in profile order, then the profile with `.`).
So a work cluster can carry `10.0.0.0/8` and everything else while a dev cluster carries
`10.50.0.0/16` and `cluster.local`:

```yaml
defaults:
  exclude: [192.168.1.0/24]
profiles:
  work:
    target: {k8s: {context: prod-eu, namespace: ops}}
    routes: [0.0.0.0/1, 128.0.0.0/1]
    dns: {domains: ["."]}
    killSwitch: {mode: on}
  dev:
    target: {k8s: {context: dev, namespace: tools}}
    routes: [10.50.0.0/16]
    dns: {domains: [cluster.local]}
    socks: 127.0.0.1:1081
```

- **Each profile on its own.** Every profile connects and reconnects by its own `reconnect`
  settings, and one that can't connect at start keeps trying by them. Its routes and names are in
  use while its tunnel is up or reconnecting; when it gives up, they are removed, as if it weren't
  running: its traffic takes the normal path or another profile's broader route (above, dev's
  addresses would go to work). subtun ends on Ctrl-C, or when every profile has given up.
- **Kill switch per profile.** A profile with a kill switch has its routes in place as soon as the
  capture starts, connected or not, and keeps them when it gives up: its traffic is refused
  rather than leaking. The kill switch
  guards only those profiles' share of the routes, and after Ctrl-C only `lockdown` profiles'
  blocks stay. While any kill switch holds, DNS to the captured servers is blocked unless every
  profile with a kill switch has `killSwitch.dns: allow`.
- **Shared settings.** The DNS servers captured are the union of the profiles'; IPv6 is blocked if
  any profile's `blockIPv6` blocks it (`auto` in a full-tunnel profile). `tun.address`, `tun.mtu`
  and `dns.fallback` exist once: profiles that set them must agree (set them in `defaults`).
- **Refused:** the same CIDR, DNS domain or SOCKS address in two profiles, and `.` in more than
  one. Two remotes that use the same addresses (two clusters with the default service range) can
  only be reached through their SOCKS proxies.
- **Config only.** With several profiles, the command line takes `--dry-run` (and the global
  flags), not settings or CIDRs; those come from the config file. The dry run lists each
  profile's routes, notes the parts another profile carries, and shows the shared DNS and kill
  switch setup.
- **Root.** Every profile tries to connect once before sudo asks, as with one profile (subtun
  waits at most 30 seconds for that). The root
  helper then stays up while subtun runs, to add and remove routes as profiles come and go. Every
  target's API server or Docker daemon address is kept out of every route, and with DNS capture
  their names never resolve through a tunnel.

## Examples

A development cluster: its pod and service ranges, and its names, from the laptop.

```yaml
profiles:
  dev:
    target: {k8s: {context: dev, namespace: tools}}
    routes: [10.96.0.0/12, 10.244.0.0/16]
    dns: {domains: [cluster.local]}
```

Private endpoints behind a VPC: a few networks, the names of the services there, and names matched
by pattern. Everything else resolves and travels as usual.

```yaml
profiles:
  work:
    target: {k8s: {context: prod-eu, namespace: ops}}
    routes: [10.20.0.0/16, 10.30.0.0/16]
    exclude: [10.20.5.0/24]
    dns:
      domains: [internal.example.com, privatelink.blob.core.windows.net]
      patterns: ['^db-[0-9]+\.prod\.example\.org$']
      unrouted: fallback
```

Everything through a remote pod, with a kill switch: traffic for the internet leaves from the pod's
network, and nothing leaks if the tunnel goes away. The pod must run outside this machine (see
[Full tunnel](#full-tunnel)).

```yaml
profiles:
  everything:
    target: {k8s: {context: remote, namespace: tools}}
    routes: [0.0.0.0/1, 128.0.0.0/1]
    dns: {domains: [".", cluster.local]}
    killSwitch: {mode: on}
```

Only a SOCKS proxy, no root needed: point a browser or `curl --socks5-hostname` at it. (Apple's git
uses a libcurl, 8.7.1, whose SOCKS support can stall: clones through a SOCKS proxy, any proxy, may
crawl. Capture the routes instead, or use a git built with a newer libcurl.)

```yaml
profiles:
  browse:
    target: {docker: {network: app_default}}
    socks: 127.0.0.1:1080
```

An office network behind an SSH gateway, reached through a bastion, as with sshuttle `-r`: the
gateway's networks and the company's names. `~/.ssh/config` still applies (a `Host office-gw`
there can hold the user, port and key instead).

```yaml
profiles:
  office:
    target: {ssh: {host: me@gw.office.example.com, jump: me@bastion.example.com, identity: ~/.ssh/work}}
    routes: [10.20.0.0/16, 10.21.0.0/16]
    dns: {domains: [corp.example.com]}
```

Everything through a host abroad, the way `sshuttle -r host 0/0 --dns` is used: every name resolved
there, nothing leaking while it's down. The host's own address is kept out of the routes
automatically, so the SSH connection itself never goes into the tunnel.

```yaml
profiles:
  abroad:
    target: {ssh: {host: me@vps.example.net}}
    routes: [0.0.0.0/1, 128.0.0.0/1]
    dns: {domains: ["."]}
    killSwitch: {mode: on}
```

Shared gateway pods: a Deployment keeps a few pods labelled `app=subtun-gw` (for clusters that allow
exec but not creating pods); subtun picks a running one at each connect, so a reconnect finds a
replacement.

```yaml
profiles:
  shared:
    target: {k8s: {context: prod-eu, namespace: ops, selector: app=subtun-gw}}
    routes: [10.20.0.0/16]
```

Two remotes at once: the cluster's ranges and names through its pod, the office's through SSH; each
connection and name goes to the profile that routes it, and each reconnects on its own. Run both
with `subtun up --profile dev,office` (more in [Several profiles at once](#several-profiles-at-once)).

```yaml
profiles:
  dev:
    target: {k8s: {context: dev, namespace: tools}}
    routes: [10.96.0.0/12, 10.244.0.0/16]
    dns: {domains: [cluster.local]}
  office:
    target: {ssh: {host: me@gw.office.example.com}}
    routes: [10.20.0.0/16]
    dns: {domains: [corp.example.com]}
```

The same from the command line:

```sh
subtun up --k8s -n tools 10.96.0.0/12 10.244.0.0/16 --dns-domain cluster.local
subtun up --k8s --context remote -n tools 0.0.0.0/1 128.0.0.0/1 --dns-domain . --dns-domain cluster.local --kill-switch on
subtun up --docker --network app_default --socks 127.0.0.1:1080
subtun up --ssh me@gw.office.example.com -J me@bastion.example.com -i ~/.ssh/work 10.20.0.0/16 10.21.0.0/16 --dns-domain corp.example.com
subtun up --ssh me@vps.example.net 0.0.0.0/1 128.0.0.0/1 --dns-domain . --kill-switch on
subtun up --k8s --context prod-eu -n ops -l app=subtun-gw 10.20.0.0/16
```

Watching and changing a run:

```sh
subtun up --profile dev,office --control full     # changes allowed from other terminals
subtun status                                     # tunnels, routes, DNS names, traffic
subtun logs -f
subtun route add --profile office 10.22.0.0/16    # without a restart
subtun profile reconnect dev
subtun tui                                        # the same in a terminal UI
```

## Routes and excludes

For any address, the most specific matching rule decides, route or exclude (sshuttle's semantics).
A prefix listed as both is excluded.

```
routes:  10.0.0.0/8, 10.205.188.50/32
exclude: 10.205.0.0/16
=> 10.0.0.0/8 is captured except 10.205.0.0/16, but 10.205.188.50 still is
```

Excludes aren't installed as routes through your normal gateway: they are carved out of the routes,
so every route subtun installs stays on its utun and disappears with it (after Ctrl-C, a crash or
`kill -9`). A /16 minus one address becomes 16 routes.

subtun cleans up the list and reports what it dropped: duplicates, routes already covered by a
broader route, and excludes that match nothing. Adjacent prefixes are merged. `--dry-run` prints
the result.

## Full tunnel

Route `0.0.0.0/1` and `128.0.0.0/1` to send everything through the tunnel. The two halves are more
specific than the real default route, which stays untouched, so when subtun exits or crashes the
machine is back to normal. Your LAN, multicast and link-local stay local (see the automatic excludes
under [Safety checks](#safety-checks)), and subtun's own connection to the API server or Docker
daemon is excluded automatically.

```sh
subtun up --k8s --context remote -n tools 0.0.0.0/1 128.0.0.0/1 --dns-domain . --dns-domain cluster.local
```

- **The target must run outside this machine.** A pod in Docker Desktop, kind or minikube reaches the
  internet through this machine, so its traffic would loop back into the tunnel. subtun warns at
  start and cuts such loops (see [Routing loops](#routing-loops)), but those addresses won't work.
- **DNS:** UDP and ICMP don't go through the tunnel yet, so a DNS server beyond your LAN isn't
  reachable through it. Add `--dns-domain .` (or `dns.domains: ["."]`) to resolve every name through
  the tunnel; list the cluster's own domain next to it when it is `cluster.local`, since `.` leaves
  `.local` names alone ([DNS](#dns)).
- **IPv6:** subtun doesn't carry it yet, so in a full tunnel it blocks outgoing IPv6 (see
  [IPv6](#ipv6)); apps fall back to IPv4.
- **Testing it:** a full tunnel also carries your remote shell or screen-sharing session. See
  [Development](development.md#full-tunnel-and-kill-switch-safely) for a way to try it safely.

## Safety checks

Before connecting or asking for sudo, subtun refuses a route that would capture your default
gateway: one at least as specific as the local network holding it (`192.168.1.0/24` when that is
your LAN). Broader routes such as `10.0.0.0/8` or a full tunnel are fine, because the LAN's own route
is more specific and keeps the gateway reachable.

It warns when a route overlaps a network of one of this machine's interfaces (your LAN, a VPN
client's interface). The more specific route wins, and the warning says which side that is.

Excluded automatically, and listed by `--dry-run`:
- subtun's own utun address;
- ranges that never belong in the tunnel, where a broader route contains them: `0.0.0.0/8`,
  loopback `127.0.0.0/8`, link-local `169.254.0.0/16`, multicast, reserved and broadcast
  `224.0.0.0/3`;
- this machine's own networks (your LAN, a VPN client's network), where a broader route contains them,
  so they stay on their interface even when other excludes split the routes around them. A route at
  least as specific as such a network (`192.168.1.128/25` on a `192.168.1.0/24` LAN) is your explicit
  choice: it stays, with the overlap warning;
- when the tunnel is up, the address subtun itself connects to (the Kubernetes API server, a remote
  Docker daemon).

### Routing loops

A target on this machine (a pod in Docker Desktop, kind or minikube, a local container) reaches the
internet through this machine. Route internet addresses through it, and its connections come back
into the tunnel, to the target again, without end. subtun guards against that:
- at start it warns when its own connection goes to this machine (a local socket or loopback) and
  the routes include internet addresses (`the target seems to run on this machine ...`);
- while running it allows at most 64 connections being opened and 256 open at once to one
  destination (address and port). A destination that hits either is refused for 10 s, with
  `refusing connections to this destination for a while: too many at once, likely a routing loop`
  in the log, once a minute per destination. A loop is cut within a second; normal programs stay far
  below both limits.

## subtun's own addresses

`tun.address` (`--tun-addr`) is the utun's point-to-point address, by default `198.18.249.1`. The
range 198.18.0.0/15 is reserved for benchmarking (RFC 2544), so real networks, VPN clients and
corporate address plans don't use it. Change it if yours does. It must be a unicast IPv4 address;
if your routes contain it, it is excluded from them.

## DNS

subtun answers the DNS queries your Mac sends to its DNS servers. Names under your `domains` or
matching your `patterns` are resolved through the tunnel by the target's own resolver (kube-dns in
a pod, Docker's DNS in a container), so you get exactly the answer the target would. Every other
name goes to a fallback resolver, as before. This is sshuttle's `--dns` with the pattern patch
(`--dns-domains`, `--dns-to`), and any number of domains costs one setting, not one file each.

```sh
build/subtun up --k8s -n team-a 10.96.0.0/12 10.244.0.0/16 --dns-domain cluster.local
curl http://web.team-a.svc.cluster.local:8080/      # any program, no proxy settings
```

| YAML (`dns:`) | Flag | Default | Meaning |
|---|---|---|---|
| `domains` | `--dns-domain` (repeatable, comma-separated) | none | suffixes resolved through the tunnel; `.` = every name except local ones |
| `patterns` | `--dns-pattern` (repeatable) | none | regular expressions resolved through the tunnel |
| `servers` | `--dns-servers` | `auto` | DNS servers whose queries are captured: `auto` (the system's) or IPv4 addresses |
| `fallback` | `--dns-fallback` | `system` | resolver for everything else: `system` (the servers the query was meant for) or `IP[:port]` |
| `capture` | `--dns-capture` | `firewall` | `firewall` (pf on macOS) or `off` |
| `unrouted` | `--dns-unrouted` | `warn` | a name resolved through the tunnel to a private address no route covers: `warn`, `fallback` or `block` (below) |

DNS capture is on as soon as `domains` or `patterns` are set, and it needs routes: it runs with the
utun capture, and the addresses it returns are reached through your routes.

**Matching.** A domain matches itself and every name below it: `company.com` matches
`company.com` and `db.eu.company.com`, not `badcompany.com`. A leading `*.`, `.` or `.*.` (sshuttle's
pattern form) is ignored, so `.*.company.com` from an sshuttle file works as is. Patterns are Go
regular expressions, matched against the lowercase name without the trailing dot. They aren't
anchored, so write `^` and `$` where you need them (sshuttle used Python's `re.match`, which anchors
at the start only).

**`.` leaves local names alone:** these go to the fallback resolver, since they belong to your
network and the target's resolver can't answer them:
- names under `local` (multicast DNS);
- names under the system's search domains (from `/etc/resolv.conf`, such as a router's `lan` or
  `home.arpa`, which also complete short names);
- reverse lookups for this machine's networks and for link-local addresses: PTR queries and Bonjour's
  browse-domain queries for the LAN (`1.168.192.in-addr.arpa` on a `192.168.1.0/24` LAN,
  `254.169.in-addr.arpa`, `e.f.ip6.arpa`).

List one to send it through the tunnel anyway: `--dns-domain . --dns-domain cluster.local`. Patterns
win the same way. The search domains and networks follow the system when the network changes (with
`servers: auto`); `--dry-run` and the log list them. Bonjour itself (multicast DNS on port 5353)
never goes near the tunnel: it isn't captured, multicast is never routed, and the kill switch leaves
it alone.

**Answers outside the routes** (`unrouted`). The target's resolver can answer with private addresses
your routes don't cover: an address in its own network, or one from a VPN on that side (one answered
`github.com` with `100.64.0.0/10` addresses). With split routes such an address goes out through your
own network, where it means nothing, or something else entirely. Private here means 10/8, 172.16/12,
192.168/16, 100.64/10, 169.254/16 and 198.18/15; public addresses outside the routes are reachable
anyway, and 0.0.0.0 or 127.0.0.1 (resolvers blocking a name) are left alone. What subtun does:
- `warn` (default): keeps the answer and logs the name and addresses, at most every 10 minutes per name;
- `fallback`: answers from the fallback resolver instead (github's public addresses, through your
  network);
- `block`: drops those addresses from the answer, so programs fail at once instead of timing out.

Like every setting, it works in `defaults:` and per profile. Routing such addresses into the tunnel
automatically is planned.

**Servers.** With `auto`, subtun reads the system's IPv4 DNS servers from `/etc/resolv.conf` and
follows them when the network changes (Wi-Fi switch, VPN up or down). IPv6 DNS servers and local
ones (`127.0.0.1`) are reported and not captured. Resolvers that only a VPN client uses for its own
domains aren't in that file and keep working as before.

**How it works on macOS.** The root helper puts a few pf rules into subtun's own anchor,
`com.apple/subtun`. The stock `/etc/pf.conf` evaluates every anchor under `com.apple/`, so the main
ruleset is never touched. The rules hand queries to those servers (UDP and TCP port 53) to subtun's
DNS listener on 127.0.0.1. Your traffic itself never goes through pf. Because the rules must be
removed again, the helper stays up for the session (one sudo prompt, as before). It removes them
when subtun exits, crashes or is killed, on Ctrl-C, and when the terminal closes. subtun's own
fallback queries leave from a port the rules let through, so they can't loop back into subtun even
when the fallback is one of the captured servers. The helper flushes macOS's DNS cache when the capture
starts, so earlier answers don't bypass it, and when it ends, so answers obtained through the tunnel
(addresses only reachable through it) don't linger. It flushes it again when a tunnel comes back
after an outage, so lookups that failed meanwhile are tried afresh, and with several profiles when
one's names start or stop going through its tunnel.

**Limits.**
- One DNS-capturing subtun at a time: a second one refuses to start, since it would take over the
  first one's rules.
- If the fallback resolver is inside one of your routes, unmatched names fail: their UDP queries go
  into the utun, which carries TCP only so far. `--dry-run` warns; exclude the resolver's address, or
  match every name with `.` (names `.` leaves local still use the fallback).
- If the helper itself is killed (`kill -9`), its rules stay and DNS for the captured servers stops
  working once subtun exits; subtun says so. The next subtun run with routes takes them over by
  itself (a SOCKS-only run only warns); `subtun cleanup` removes them without starting a session.
- macOS only for now; `override` and `supplemental` capture modes (via the system resolver
  configuration instead of the firewall) are planned.

## Kill switch

Without a kill switch, when subtun stops or crashes its routes disappear with the utun, and traffic
for those CIDRs goes out the normal way again (your LAN, your ISP, another VPN). That's fine for
reaching a dev cluster; it's a leak when the point is that this traffic must never leave any other
way. The kill switch blocks it with firewall rules.

| `killSwitch.mode` / `--kill-switch` | While running | subtun crashes, is killed, or the tunnel is lost | You stop it (Ctrl-C, terminal closed) |
|---|---|---|---|
| `off` (default) | no blocking | normal networking | normal networking |
| `on` | traffic for the routes can only leave through the tunnel | blocks stay | blocks removed |
| `lockdown` | the same | blocks stay | blocks stay |

| `killSwitch.dns` / `--kill-switch-dns` | While the blocks stay, with DNS capture |
|---|---|
| `block` (default) | DNS to the captured servers is blocked too: no name leaks to your normal resolver, and a private-link name can't resolve to a public endpoint. All DNS through those servers fails until subtun runs again or you clean up. Lookups don't fail at once but wait for the program's DNS timeout (`dig`: 5 s), since resolvers ignore the firewall's refusal of UDP |
| `allow` | DNS works normally (names may leak); only the routed traffic stays blocked |

What is guarded: your routes minus local networks more specific than them. Your LAN inside a full
tunnel stays reachable, as it does through the routing table, and a VPN client's own network stays
with that client. A route more specific than such a network (a CGNAT /24 inside a VPN client's
/16) stays guarded, since without subtun it would fall back to that network. The guard follows the
machine's networks while subtun runs: join another Wi-Fi with another subnet and, within about 5
seconds, that LAN (router, DHCP) is left out and the previous one guarded again. subtun's own
connection to the API server or Docker daemon is never blocked. With `--dry-run`, subtun shows how
many prefixes it would guard.

While the blocks stay, the next run of subtun with routes takes them over (a SOCKS-only run only
warns about them): it asks for sudo before connecting,
keeps blocking but allows DNS (so it can resolve the API server) and replaces them once the tunnel is
up. If that start fails, the blocks are put back. To get back to normal without starting a session:

```sh
subtun cleanup      # sudo asks once; refuses while a subtun session is running
```

Notes:
- In a full tunnel with a kill switch, other VPN clients' own connections (to their servers on the
  internet) are blocked too: everything outside the tunnel is.
- After a reboot the blocks are gone (pf rules live in memory).
- The kill switch needs routes (without them it's ignored, with a warning), and keeps the root
  helper running for the session.

## Reconnect

When the connection to the agent is lost (the pod restarted, the laptop slept, a network change broke
it), subtun tries to connect again instead of exiting. Meanwhile the utun, the routes, the firewall
rules and the SOCKS listener stay: new connections and names resolved through the tunnel fail at
once, nothing leaks around the tunnel (with or without a kill switch), and connections that were open
are lost. Once connected again, everything works as before; the log says `reconnected ... after`.

| YAML (`reconnect:`) | Flag | Default | Meaning |
|---|---|---|---|
| `attempts` | `--reconnect-attempts` | `10` | tries per outage; `0` exits at once, as before |
| `delay` | `--reconnect-delay` | `1s` | the wait before the first try; it doubles after each one |
| `maxDelay` | `--reconnect-max-delay` | `1m` | the longest wait between tries |

Waits vary by ±20 %, so several clients don't retry in step. With the defaults subtun gives up after
about 5 minutes without a connection and exits with an error; a kill switch then keeps its blocks
(mode `on`). After a successful reconnect the count starts over. Like every setting, it works in
`defaults:` and per profile, and the flags override both.

A reconnect finds the target by the same name. A pod a Deployment recreated has a new name, so subtun
can't find it; target pods that keep their name (a bare pod, a StatefulSet's) or a container.

## IPv6

subtun captures IPv4 only so far. On a dual-stack network, apps would prefer IPv6 for names that
have both, and that traffic would bypass a full tunnel entirely. So subtun blocks outgoing IPv6:

| `blockIPv6` / `--block-ipv6` | Effect |
|---|---|
| `auto` (default) | blocked when the routes cover all of IPv4 (`0.0.0.0/1` + `128.0.0.0/1`), not for split routes |
| `true` | blocked whenever subtun captures |
| `false` | never blocked |

Link-local (`fe80::/10`), multicast (`ff00::/8`) and loopback stay allowed, so the local network
keeps working; blocked connections are refused at once, so apps fall back to IPv4 quickly. If
subtun's own connection to the API server uses IPv6, IPv6 is left alone, with a warning. The block
is removed when subtun stops, unless a kill switch keeps its blocks in place (then IPv6 stays blocked
with them).

## Status and logs

Every running subtun answers `subtun status` and `subtun logs` through a control socket that only
your user can use (in `~/.local/state/subtun/run`, or `$XDG_RUNTIME_DIR/subtun` when set; no root, no
network port).

```sh
subtun status                    # every running subtun
subtun status --watch            # refreshed every second, until Ctrl-C
subtun status --connections      # with the open connections
subtun status --json             # for scripts
subtun logs                      # the recent log lines it keeps in memory
subtun logs -f                   # then follow new ones (--pid N when several run)
```

For each tunnel (one per profile): its state (connecting, up, reconnecting with the attempt and
the next try, gave up, stopped) and the last error, the target and agent, its routes and whether they are in
use, its DNS names, kill switch and SOCKS address, and counters: connections (open, total, failed,
through SOCKS), bytes each way with the rate of the last second, the names it answered, and
connections the loop guard refused. Then the shared DNS capture (the servers captured now, the
fallback, the names that stay local) and the kill switch (guarded prefixes).

`subtun logs` shows the lines subtun prints, kept in memory (at most 5000 lines or 4 MB, so a long
run keeps its latest lines); the log file below keeps them on disk. With debug levels they include
every name resolved and every connection captured; `subtun logs` shows them only to your user, like
the terminal does.

| Setting | Flag | Values |
|---|---|---|
| `control` (top level of the config file, next to `defaults:`) | `--control` | `status` (default), `full` (also [changes](#changes-while-running)), `off` (no socket) |

`control` is set once for the whole run, never per profile; a target given on the command line
(`--k8s`, `--docker`) takes the config file's key too (`--control` wins).

## Log files

Every run also writes its log to a file, one per start, in `~/.local/state/subtun/logs`
(`$XDG_STATE_HOME/subtun/logs` when set): `subtun-<start time>-<pid>.json`, one JSON object per
line, with the component that logged it. A long run starts a new part at `log.maxSize`
(`...-2.json`, `...-3.json`); at start and every hour subtun removes its log files older than
`log.maxAge`, then the oldest while all of them take more than `log.maxTotal`: only files named
as subtun's, never one another running subtun writes. The default directory is yours only (0700);
files are 0600.

```yaml
log:
  file: on              # off: no file
  format: json          # or text
  level: info           # and per component, in one line: "info,dns=debug"
  levels:
    dns: debug          # every DNS query, without every other debug line
  maxSize: 20MB
  maxAge: 3d
  maxTotal: 500MB
  mask: [dns, destinations]
```

| Setting | Flag | Values |
|---|---|---|
| `log.file` | `--log-file` | `on` (default), `off` |
| `log.dir` | `--log-dir` | default `~/.local/state/subtun/logs` |
| `log.format` | `--log-format` | `json` (default), `text` |
| `log.level` | `--log-level` | `debug`, `info` (default), `warn`, `error`, plus `component=level` pairs |
| `log.levels` | (in `--log-level`) | per component: `tunnel`, `dns`, `conn`, `capture`, `helper`, `control`, `socks`, `transport` |
| `log.maxSize` | `--log-max-size` | `20MB` |
| `log.maxAge` | `--log-max-age` | `3d` (also `12h`, `90m`) |
| `log.maxTotal` | `--log-max-total` | `500MB` |
| `log.mask` | `--log-mask` | `dns`, `destinations`, both, none (default) |

- **Levels** apply to the terminal, `subtun logs` and the file alike. The components: `tunnel`
  (connecting, reconnecting, changes while running), `dns` (every query at debug, answers that point
  outside the routes), `conn` (every captured connection at debug), `capture` (utun, routes,
  firewall, kill switch), `helper` (the root helper), `control`, `socks` (every connection through
  the proxy at debug), `transport` (reaching the pod or container, the agent). `-v` is debug for
  all. `--log-level info,dns=debug` is all you need to follow DNS.
- **Masking** replaces DNS names and destinations (connections, the addresses answers point at, the
  ones errors repeat, and the agent's own lines at debug) by short hashes: the same name or address gives the same hash during a
  run, nothing links two runs. A masked name keeps the configured domain it falls under
  (`h3fa9c1.corp.example`), else its last two labels (a name of one or two labels becomes just
  the hash, `h3fa9c1`); a SOCKS destination given by name is masked as a name. Useful to share a log; leave it off to investigate. Other lines (routes, DNS servers, the
  root helper's) aren't masked.
- `log` is set once for the whole run, never per profile (as `control`); flags win over the file,
  and `--log-level` replaces both `log.level` and `log.levels`.

## Changes while running

A subtun started with `control: full` (or `--control full`) takes changes through its control
socket, without a restart: routes, DNS names, and stopping, starting or reconnecting one of its
profiles while the others go on.

```sh
subtun up --profile work,dev --control full

subtun route add --profile dev 10.70.0.0/16 10.71.0.5   # route these through dev's tunnel too
subtun route add --profile work -x 10.1.0.0/16          # an exclude: never routed
subtun route del --profile dev 10.70.0.0/16             # a route it has, configured or added
subtun dns add --profile dev corp.example --pattern '^db[0-9]+\.'
subtun dns del --profile dev corp.example
subtun profile stop dev                                 # as Ctrl-C, for dev only
subtun profile start dev                                # connect it again
subtun profile start dev --reload                       # ... reading it from the config file again
subtun profile reconnect work                           # drop its connection and connect again now
subtun log level info,dns=debug                         # log every DNS query from now on (subtun log level: show)
subtun profile start vault                              # add a profile of the config file to the run
subtun route add --profile dev 10.80.0.0/16 --dry-run   # only show what would change
```

- **Checked as at start.** Each change is planned like the profile was: the routes against the
  machine's networks (the safety checks, the automatic excludes), subtun's own endpoints carved out,
  the same CIDR or DNS domain (or `.`) in two profiles refused. A refused change changes nothing.
  The utun's routes, the kill switch's guard, which tunnel carries an address and the DNS matcher
  follow at once; the system's DNS cache is flushed after a DNS change.
- **Which profile.** `--profile` (or the `NAME` of `subtun profile`) can be left out when the run
  has one profile. With several running subtuns, choose one with `--pid`.
- **Temporary.** Changes last until subtun stops; nothing is written to the config file.
  `subtun status` lists them per profile ("changed while running").
- **`profile stop`** is Ctrl-C for that profile: its routes and DNS names are removed, and its
  traffic goes the normal way again. With `killSwitch.mode: on` its blocks are lifted too; with
  `lockdown` its routes stay and its traffic is refused until it starts again. Its SOCKS proxy
  refuses connections meanwhile. subtun goes on even with every profile stopped (Ctrl-C ends it).
- **`profile start`** connects a stopped profile, or one that gave up while others run, again, with
  the settings it had: the ones it started with and the changes made since. As without changes,
  subtun ends when every profile has given up (one profile: when it gives up), also when that
  follows a start or reconnect that failed; a kill switch then keeps its blocks. With `--reload` it reads the profile
  from the config file the run started with instead (command-line flags of `subtun up NAME` still
  apply), dropping the changes made while running. A reload takes the target, agent, routes,
  excludes, DNS domains and patterns, SOCKS address and reconnect settings; the settings the run
  shares or set up at start (`tun.*`, `dns.capture`, `dns.servers`, `dns.fallback`, `dns.unrouted`,
  `killSwitch.*`, `blockIPv6`) need a restart, and a reload that changes them is refused, as is
  one that adds DNS names asked of servers the run doesn't capture, or moves the target to an
  IPv6 address while IPv6 is blocked.
- **`profile start NAME` of a profile that isn't part of the run** adds it from the config file the
  run reads (`--config`, `$SUBTUN_CONFIG` or the default), with the config's settings only, as
  `subtun up --profile a,b` takes them; it is checked against the running profiles as at start:
  `tun.*` and `dns.fallback` it sets must agree with the run's, no CIDR, DNS domain (or `.`) or
  SOCKS address in two profiles. It needs what the run set up at start: routes only if the run has a
  utun capture, a kill switch only if the run's capture has one (a profile had a kill switch when it
  started). Its DNS names are ignored, with a warning, when the run doesn't capture DNS; they are
  refused when their DNS servers aren't among those the run captures. Once the capture runs, a
  `killSwitch.dns` other than the run's, or a full tunnel's IPv6 block, only bring a warning (the
  capture set them up at start). An added profile stays part of the run until it ends (`profile
  stop` stops it); a run of one profile becomes a run of several (it ends when every profile has
  given up). Runs of a target given on the command line (a tunnel without a profile name) take no
  added profiles.
- **`profile reconnect`** drops the profile's connection and connects again at once, then by its
  reconnect settings; its routes stay meanwhile, as when a connection is lost.
- **`log level SPEC`** replaces the run's log levels (as `--log-level`: `info,dns=debug`); the
  terminal, `subtun logs`, the terminal UI and the log file all follow, until subtun stops.
- **Limits for now.** Routes can be added to a profile that started with routes (not to a
  SOCKS-only one), and a profile keeps at least one route (stop it instead). DNS names can be added
  when the run captures DNS already (a profile had DNS names when it started), and only for a
  profile whose DNS servers it captures: which servers are captured, and whether the system's are
  followed, was decided at start by the profiles that had names then.

With `control: full` the root helper stays up for the whole run, also for one profile with routes
only (otherwise it exits after setup), so routes can change without a sudo prompt: any program
running as your user can then change subtun's routes. The routes can only point into subtun's utun,
and the helper checks each one.

## Terminal UI

`subtun tui` attaches to a running subtun through its control socket (`--pid N` when several run)
and shows it in the terminal. `q` quits the TUI; subtun goes on.

```sh
subtun up --profile work,dev --control full    # in one terminal
subtun tui                                     # in another
subtun tui --layout detail
```

Or run subtun with the TUI in the same terminal: `--tui` on `subtun up`, `k8s` and `docker`.

```sh
subtun up work --tui
subtun up --profile work,dev --tui
```

- It is the same TUI, with what subtun logs in its log views instead of on the terminal (the log
  file is written as always). What else would write to the terminal meanwhile, such as a kubeconfig
  login plugin's messages, shows in the log views too (`stderr: …`).
- A kubeconfig login plugin can't ask you anything meanwhile (the TUI has the keyboard): one that
  needs to (a password, say) fails, saying so. Log in first (`kubectl get pods`, say), then start
  subtun. A browser login still works.
- It makes changes whatever `control` says: it is your own terminal. `control` still decides what
  other terminals can do through the socket.
- When sudo needs the password for the root helper (at the start, or when a profile with routes is
  added), the TUI steps aside: the terminal shows sudo's prompt (or Touch ID asks), and the TUI
  comes back once the helper runs. It doesn't when sudo needs no password then (checked with `sudo
  -n -v`, which may leave a "password required" line in the system log, and which with a sudoers
  rule for subtun alone still says a password is needed: the TUI then steps aside for nothing).
- `q` (or Ctrl-C) asks before stopping subtun, saying what each profile's kill switch then does; a
  second Ctrl-C stops at once. The TUI shows the stop until the routes and firewall rules are off.
  A signal (`kill`) stops subtun as without the TUI.
- When it closes, the log lines of the stop are printed (or the last 20 when subtun stopped by
  itself, such as when every profile gave up).
- It needs a terminal, and doesn't go with `--dry-run`.

- **Dashboard:** every profile with its state, target, routes, DNS names, kill switch, the rate each
  way and a gauge of its traffic now (against the scale of its last 5 minutes); below, the log lines
  of every profile (a line no profile logged names its source, such as `helper`). Two layouts,
  switched with `v`: `table` (the profiles above the logs) and `detail` (a list, and the selected
  profile's detail with its traffic graph next to it). The dashboard's logs are every profile's;
  the profile screen has its own.
- **Profile screen** (`enter`): its name, state, target, agent and kill switch in the header; then
  panes, each shown or hidden with `1` to `4` and remembered:
  - `2` traffic: where its own connection goes (the kube context, the API server or Docker host and
    its addresses), its counts, and next to them its traffic graph of the last 5 minutes (upload
    above a zero line, download below, each against its own round scale, coloured by height);
  - `1` config: what it asks for, on two tabs (`t`): its routes and excludes (each marked
    configured, or added or removed while running with the time, with what of it another profile
    carries or subtun's own endpoint taken out), or its DNS names (with the unrouted-answers mode);
    the tab's keys are on its first line;
  - `3` its open connections, next to the config;
  - `4` its log lines (`L`: full screen).
- **Units:** `u` switches the rates between bytes and bits a second (`MB/s`, `Mb/s`).
- **Mouse:** a click selects, a double-click opens a profile, the wheel scrolls (scrolling the logs
  back pauses them). `m` turns it off, for the terminal to select text again (most terminals also
  select with shift or option held).
- **Dialogs:** tab or the arrow keys move between the fields and buttons; the focused button is
  highlighted.
- **Logs** (`l`, or `/` to search them): full screen, filtered by profile (`p`), by level (`d`,
  `i`, `w`, `e` show or hide debug, info, warn and error lines; also in the other log views while
  focused) and text (`/`: the time, profile, level and message); `f` follows or pauses. They are
  the lines `subtun logs` shows; the TUI saves nothing. `V` changes what subtun itself logs (its
  default level and each component's, as `subtun log level`).
- **Changes** (a run with `control: full`): `s` stop (the confirm says what the profile's kill switch
  then does), `S` start, `r` reconnect, and on the profile screen `R` reload from the config file,
  `a` add (a route, or on the DNS tab DNS names), `x` an exclude, `A` DNS names, `d` delete the
  selected one; on the dashboard `a` adds a profile of the config file (those that can't join say
  why); `V` the log levels. Each dialog shows the change's dry run first, as `--dry-run` does; the
  changes are those of [Changes while running](#changes-while-running), and last until subtun
  stops. A run with `control: status` shows everything and greys the change keys out.
- `?` lists the keys. The TUI follows the terminal's size: in a narrow one the table drops its
  target, DNS, sparkline and kill-switch columns, in that order, and dialogs shrink to fit.

| Setting | Flag | Values |
|---|---|---|
| `tui.layout` (top level of the config file) | `--layout` | `table` or `detail`; unset: the layout used last (kept in `~/.local/state/subtun/tui.json`), else `table` |
| `tui.units` | `--units` | `bytes` or `bits`; unset: the units used last, else `bytes` |
| `tui.mouse` | `--mouse` | `on` or `off`; unset: as used last, else `on` |

`tui` is read by `subtun tui` and `--tui` only, never per profile. `tui.json` also keeps how the TUI was left:
the profile screen's hidden panes and config tab, and the log levels the views hide.

## Importing from sshuttle

`subtun import sshuttle FILE` reads an sshuttle options file (the `@FILE` format: one argument per
line, `#` comments) and makes a named profile from it (`--name`, default `imported`):

```sh
subtun import sshuttle work.conf --name work > work.yaml                    # review it first
subtun import sshuttle work.conf --name work --write                        # add it, through its SSH remote
subtun import sshuttle work.conf --name work --k8s debug -n tools --write   # or through a pod instead
```

| sshuttle | subtun profile |
|---|---|
| subnets, `-s FILE` | `routes`; duplicates and routes covered by a broader one are dropped; host bits are cleared; `0/0` becomes `0.0.0.0/1` + `128.0.0.0/1` |
| `-x`, `-X FILE` | `exclude`; excludes that match no route are dropped |
| `--dns` alone | `dns.domains: ["."]` (every name through the tunnel) |
| `--dns-domains` `.*.company.com` | `dns.domains: [company.com]` (now also matches `company.com` itself, and only on label boundaries) |
| other `--dns-domains` patterns | `dns.patterns`, anchored with `^` as sshuttle's `re.match` was; check them, Python and Go regexps differ in details |
| `--dns-to IP:PORT` | `dns.fallback` |
| `--ns-hosts` | `dns.servers` |
| `-r [user[:password]@]host[:port]` | `target: {ssh: {host: ...}}`; the password is left out (subtun logs in with keys or the SSH agent) |
| `-e "ssh -i KEY -J JUMP -p PORT -l USER ..."` | `identity`, `jump`, and the port and user when `-r` has none; other ssh options are listed (set them in `~/.ssh/config`) |

Options subtun doesn't need or have (`--method`, `--no-latency-control`, `-N`, ...), names and IPv6
subnets, and port ranges are listed in comments above the profile, together with what was dropped
as redundant. The target is sshuttle's SSH remote; `--k8s POD` (`-n`, `--context`) or `--docker
CONTAINER` give an existing pod or container instead. Without any of them the printed profile has a
placeholder.

`--write` adds the profile to your config file (`--config`, `$SUBTUN_CONFIG` or the default) right
below `profiles:`, with the indentation of your other profiles, keeping comments and everything else.
It needs a target (sshuttle's `-r`, `--k8s` or `--docker`), refuses if the name is taken or the result wouldn't load,
and keeps the old file as `.bak`.

