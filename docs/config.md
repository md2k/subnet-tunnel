# Configuration

Everything can be given on the command line, or kept in named profiles in a YAML file and started
with `subtun up NAME`.

## File

Location: `--config FILE`, else `$SUBTUN_CONFIG`, else `$XDG_CONFIG_HOME/subtun/config.yaml`, else
`~/.config/subtun/config.yaml`. Parsing is strict: an unknown key is an error, so a typo can't
silently drop a setting.

```yaml
defaults:                          # optional: any profile key except target, for every profile
  exclude: [192.168.1.0/24]
  killSwitch: {mode: on}

profiles:
  dev-cluster:                     # a lowercase letter or digit, then also '.', '_', '-'
    target:                        # exactly one of k8s / docker
      k8s:
        kubeconfig: ~/.kube/dev    # default: $KUBECONFIG or ~/.kube/config
        context: dev               # default: current context
        namespace: tools           # default: the context's namespace
        pod: debug                 # required
        container: shell           # default: kubectl's default container
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

  local-app:
    target:
      docker:
        host: unix:///var/run/docker.sock   # default: $DOCKER_HOST, then the docker context
        context: desktop-linux               # default: $DOCKER_CONTEXT, then the current context
        container: app                       # required
    socks: 127.0.0.1:1081
```

A profile needs `routes`, `socks` or both (its own or from `defaults`).

**Defaults.** Settings under `defaults` apply to every profile. A profile's own value wins; lists
(`routes`, `exclude`, `dns.domains`, `dns.patterns`) add up, so a home-LAN exclude in `defaults`
applies everywhere. Settings that need routes (DNS capture, the kill switch, IPv6 blocking) are
ignored, with a warning, in a profile without routes, so a kill switch in `defaults` doesn't break
a SOCKS-only profile. YAML treats bare `on`, `off`, `yes` and `no` as booleans; subtun reads them as
the words you meant (`mode: off`, `capture: off` work).

## Commands

| Command | What it does |
|---|---|
| `subtun k8s POD [CIDR...]` | tunnel through a pod (`-n`, `-c`, `--context`, `--kubeconfig`) |
| `subtun docker CONTAINER [CIDR...]` | tunnel through a container (`-H`, `--context`) |
| `subtun up [PROFILE] [CIDR...]` | run a profile from the config file; without a name, list them |
| `subtun cleanup` | remove firewall rules an earlier session left (a kill switch's blocks), without starting one |
| `subtun import sshuttle FILE` | turn an sshuttle options file into a profile ([below](#importing-from-sshuttle)) |
| `subtun version` | print the version |

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
a config file, the same flags work on `subtun k8s` and `subtun docker`.

## Examples

A development cluster: its pod and service ranges, and its names, from the laptop.

```yaml
profiles:
  dev:
    target: {k8s: {context: dev, namespace: tools, pod: debug}}
    routes: [10.96.0.0/12, 10.244.0.0/16]
    dns: {domains: [cluster.local]}
```

Private endpoints behind a VPC: a few networks, the names of the services there, and names matched
by pattern. Everything else resolves and travels as usual.

```yaml
profiles:
  work:
    target: {k8s: {context: prod-eu, namespace: ops, pod: toolbox}}
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
    target: {k8s: {context: remote, namespace: tools, pod: egress}}
    routes: [0.0.0.0/1, 128.0.0.0/1]
    dns: {domains: [".", cluster.local]}
    killSwitch: {mode: on}
```

Only a SOCKS proxy, no root needed: point a browser or `curl --socks5-hostname` at it.

```yaml
profiles:
  browse:
    target: {docker: {container: app}}
    socks: 127.0.0.1:1080
```

The same from the command line:

```sh
subtun k8s -n tools debug 10.96.0.0/12 10.244.0.0/16 --dns-domain cluster.local
subtun k8s --context remote -n tools egress 0.0.0.0/1 128.0.0.0/1 --dns-domain . --dns-domain cluster.local --kill-switch on
subtun docker app --socks 127.0.0.1:1080
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
subtun k8s --context remote -n tools egress 0.0.0.0/1 128.0.0.0/1 --dns-domain . --dns-domain cluster.local
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
build/subtun k8s -n team-a debug-pod 10.96.0.0/12 10.244.0.0/16 --dns-domain cluster.local
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
(addresses only reachable through it) don't linger.

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

## Importing from sshuttle

`subtun import sshuttle FILE` reads an sshuttle options file (the `@FILE` format: one argument per
line, `#` comments) and makes a named profile from it (`--name`, default `imported`):

```sh
subtun import sshuttle work.conf --name work > work.yaml                    # review it first
subtun import sshuttle work.conf --name work --k8s debug -n tools --write   # add it to your config
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

Options subtun doesn't need or have (`--method`, `--no-latency-control`, `--remote`, `-N`, ...),
names and IPv6 subnets, and port ranges are listed in comments above the profile, together with what
was dropped as redundant. The target can't come from sshuttle's SSH remote: give `--k8s POD`
(`-n`, `--context`) or `--docker CONTAINER`; without one the printed profile has a placeholder.

`--write` adds the profile to your config file (`--config`, `$SUBTUN_CONFIG` or the default) right
below `profiles:`, with the indentation of your other profiles, keeping comments and everything else.
It needs a target (`--k8s` or `--docker`), refuses if the name is taken or the result wouldn't load,
and keeps the old file as `.bak`.

