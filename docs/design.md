# Design

Status: early development. This document records the measurements that drove the design and the
decisions taken so far.

## Problem

sshuttle on macOS, tunnelling into a Kubernetes pod over `kubectl port-forward`:

- download: fast
- upload: very slow

A SOCKS proxy over the same port-forward was fast in both directions, so the transport was fine.

## What limits sshuttle on macOS

1. **Latency control** ([sshuttle#349](https://github.com/sshuttle/sshuttle/issues/349)): sshuttle limits
   in-flight data until a ping/pong round trip completes. `--no-latency-control` removes it.
2. **pf `rdr` + `route-to lo0`** ([sshuttle#752](https://github.com/sshuttle/sshuttle/issues/752),
   [Apple forum 694804](https://developer.apple.com/forums/thread/694804)): the way sshuttle captures
   traffic on macOS. On Monterey to Sequoia, upload collapses to a few KB/s after the first ~200 KB.
   The issue reproduces without sshuttle, using only the pf rules.

## Measurements

### Capture

Clean MacBook, macOS 27.0.1, no VPN or endpoint security software. Python test scripts on
loopback and a local Kubernetes cluster (Docker Desktop). 50 MB transfers.

| Path | Upload | Download |
|---|---|---|
| Loopback, no capture | ~2.8 GB/s | ~1.7 GB/s |
| pf `rdr` + `route-to lo0` | **~3.9 MB/s** | instant |
| utun + tun2socks (gVisor), local | ~141 MB/s | ~450 MB/s |
| `kubectl port-forward` to a pod (transport limit) | 245 MB/s | 274 MB/s |
| SOCKS5 relay in pod over port-forward | ~270 MB/s | — |
| utun + tun2socks → port-forward → pod, default MTU | ~76 MB/s | ≈ port-forward |
| same, utun MTU 9000 | **~170 MB/s** | ≈ port-forward |

Findings:

- On macOS 27 the pf `route-to` leg is a steady ~30 Mbit/s cap on upload. Download, which returns
  through rdr without `route-to`, is not affected. That matches sshuttle's "download fast, upload slow".
- Capturing with utun and a userspace stack removes that cap.
- Larger gVisor buffers made no difference to upload. A larger utun MTU more than doubled it, so the
  remaining upload cost is per packet. tun2socks's own Linux benchmark shows the same ratio
  (upload about 70% of the raw transport).

### Transport: exec stdio vs port-forward

Corporate MacBook (with a VPN client and endpoint security software), Docker Desktop with its
bundled Kubernetes. 500 MB per transfer, average of three runs, `curl` through subtun's SOCKS5
proxy to a separate HTTP service behind the agent.

| Path | Download | Upload |
|---|---|---|
| `kubectl port-forward` to the service (transport limit) | ~271 MB/s | ~237 MB/s |
| subtun: exec (WebSocket) → smux → agent → service | ~212–228 MB/s | ~175–182 MB/s |
| subtun: Docker exec → smux → agent → container | ~255 MB/s | ~177 MB/s |

The exec carrier reaches about 80% of raw port-forward downstream and about 75% upstream, with the
multiplexer, an extra in-cluster TCP hop and the SOCKS layer included. That is far above what a
remote cluster's round-trip time will allow, so exec stays the carrier.

### Transparent capture: utun vs SOCKS vs port-forward

Clean MacBook (macOS 27.0.1, arm64, no VPN or endpoint security software), Docker Desktop with its
Kubernetes, 500 MB, best of two runs, to the same HTTP service.

| Path | Download | Upload |
|---|---|---|
| raw `kubectl port-forward` (transport limit) | 287 MB/s | 280 MB/s |
| SOCKS → k8s exec → agent | 249 MB/s (87 %) | 215 MB/s (77 %) |
| **utun + gVisor → k8s exec → agent** | **232 MB/s (81 %)** | **193 MB/s (69 %)** |
| utun + gVisor → Docker exec → agent | 210 MB/s | 147 MB/s |

Capture through utun costs about 6–10 % against SOCKS, and upload beats the ~170 MB/s that
utun + tun2socks reached over port-forward in the capture measurements above. Upload through the
Docker transport is lower than through Kubernetes (open question below).

Verified in the same run: the helper exits after setup (no root process left), the utun and its
routes disappear after Ctrl-C and after `kill -9` of subtun, an interrupted or failed sudo leaves
nothing behind, and a refused destination fails in ~10 ms (TCP reset) instead of timing out.

### Agent: Go binary vs Python

Same laptop, same `python:3.14-alpine` container, Docker exec, 500 MB, two runs each.

| Agent | Upload | Download |
|---|---|---|
| Go binary | 182–187 MB/s | 243–245 MB/s |
| Python 3.14 | 179–184 MB/s | 235–242 MB/s |

The Python agent is within a few percent of the Go one: the remote side is not the bottleneck, as
already seen with a Python SOCKS relay in the capture measurements above. Python 3.6 (the oldest
supported) reached ~92 MB/s up and ~263 MB/s down in a shorter 50 MB run.

## Architecture

```
app ──► utun + gVisor  ──┐
        (routed CIDRs)   ├─► tunnel client ══ carrier ══► agent ──► destination
app ──► SOCKS5 proxy  ───┘   smux streams    exec stdio   in the target
        on the laptop
```

- **Capture** (`internal/capture`, `internal/netstack`, `internal/tundev`). The root helper creates
  a utun interface (MTU 9000, address 198.18.249.1) with routes for the given CIDRs and passes its
  file descriptor to subtun. A gVisor stack on the utun runs in promiscuous mode with spoofing, so
  it terminates TCP connections to any routed destination. Each connection is dialed through the
  tunnel *before* the handshake with the local app completes: an unreachable destination gets a
  TCP reset, as on a real network. TCP settings follow tun2socks (SACK, RACK, no Nagle delay).
  SOCKS and capture call the same `DialContext` on the tunnel client; the agent can't tell them
  apart.
- **Routes** (`internal/routes`). Routes and excludes combine like sshuttle's: for any address the
  most specific rule decides. Excludes are carved out of the routes rather than installed via the
  normal gateway, so every route stays on the utun and disappears with it. Redundant rules are
  dropped and reported, siblings merged. Ranges that never belong in the tunnel (0/8, loopback,
  link-local, multicast/reserved/broadcast) and the machine's own networks are excluded
  automatically where a broader route contains them. So the LAN stays on its interface even when
  an exclude inside it (the API server) splits the routes into pieces more specific than the LAN's
  route, and no piece starts at a multicast address, which the helper would refuse. The kill
  switch guards the final routes, so it never blocks DHCP, Bonjour or link-local either. Before
  connecting, routes covering subtun's utun address or the default gateway are refused and
  overlaps with local interface networks are reported. At
  connect time the API server or Docker daemon address is excluded automatically. Details:
  [Configuration](config.md).
- **Routing loops.** A target on this machine (Docker Desktop, kind, minikube) reaches the internet
  through this machine. Route internet addresses through it, and its connections come back into the
  tunnel, to the target again, without end.
  - The stack caps the connections to one destination (address and port): 64 still opening at
    once, which catches a proxy that connects onward before accepting (Docker Desktop's: measured
    on the test Mac, cut in 0.4 s), and 256 open at once, for one that accepts first.
  - A destination that hits a cap is refused for 10 s, so the chain unwinds and retries don't build
    a new one. One warning per destination a minute; the failures of an unwinding loop, and repeats
    of any failed connect, are logged at debug level.
  - Normal clients stay far below both caps. Clients that open and close many connections in a row
    don't add up, since only concurrent connections count.
  - The global limit on connections opening at once is 4096, so a full tunnel looping through a
    local target (dozens of destinations at once) doesn't starve the destinations that work.
  - subtun also warns at start when its own connection goes to this machine (a unix socket or
    loopback) and the routes include internet addresses.
  - So a full tunnel needs a target outside this machine.

- **Agents.** Two implementations of the same protocol; `--agent auto` uses the first that can run.
  - *Binary:* a static Linux Go binary (`cmd/subtun-agent`, ~3.5 MB) embedded in subtun for amd64
    and arm64. One probe exec reports the architecture, cached builds, a usable directory and any
    Python. The directory is the first of `$XDG_CACHE_HOME`/`~/.cache/subtun`, `/tmp/subtun-<uid>`,
    `/var/tmp/subtun-<uid>`, `/dev/shm/subtun-<uid>` that can be created as a 0700 directory owned
    by us, is writable and allows exec (tested by running a two-line script there, which catches
    noexec mounts and security policies). Directories we don't own are skipped, so nobody else can
    plant a binary for us to run. The upload is cached under the checksum; older builds in the
    directory are removed.
  - *Python:* `internal/agentpy/agent.py`, standard library only, Python 3.6+. Sent over the exec
    session's stdin and run from memory with `python3 -c <loader>`, the way sshuttle starts its
    server, so nothing is written to the target and no shell is needed. It implements the smux v2
    server side (framing, per-stream windows, keepalive) and the same request/response.
  - Fallback: no shell (distroless Python) or no usable directory (read-only root, noexec tmpfs)
    → Python. The error lists every directory tried and why it failed.
- **Carrier.** The agent's stdin/stdout over the exec API: Kubernetes through client-go (WebSocket,
  SPDY fallback) with the user's kubeconfig; Docker through the Engine API with the user's docker
  context. No kubectl, port-forward or sshd involved.
- **Protocol.** The agent first writes a hello line (`subtun-agent <proto> <version> <sha256>`);
  subtun checks the protocol version and that the checksum matches what it sent (binary or Python
  source). Then
  smux v2 runs over the carrier, one stream per connection: a request (`connect host:port`), a
  status reply, then raw bytes. Hostnames resolve on the agent side. Half-close passes through.
- **Flow control.** smux per-stream window 4 MB, session buffer 32 MB, so one stream is not capped
  at window/RTT on remote clusters.
- **DNS** (`internal/dns`). Queries the system sends to its DNS servers are redirected to subtun's
  DNS engine, which resolves matching names through the tunnel and everything else through a
  fallback resolver. See [DNS](#dns).
- **Lifecycle.** Closing subtun sends EOF on the agent's stdin and the agent exits. If the carrier
  drops (pod deleted, network lost), subtun notices within seconds (smux keepalive: 30 s at most)
  and reconnects: the capture, the SOCKS proxy and DNS reach the agent through one swappable
  client, which fails dials and DNS at once while it's down; utun, routes and firewall rules stay.
  Tries per outage, the first wait and the longest wait are settings (`reconnect`); waits double
  with ±20 % jitter, and after the last try subtun exits with an error (a kill switch then holds).

## Privileges

subtun runs as the user. Creating a utun interface, adding routes and loading firewall rules (DNS
capture, kill switch, IPv6 block) need root; packet handling and DNS answering never do. Root work
is done by a small helper, `subtun helper`, that subtun starts through `sudo` (sudo asks for the
password on the terminal).

### How the helper is trusted

- subtun creates a unix socket in a private directory (`~/Library/Caches/subtun/run`, mode 0700,
  socket 0600) and starts `/usr/bin/sudo -- <subtun> helper --socket <path>`, passing a random
  token on the helper's stdin.
- The helper refuses to run unless it is root and started through sudo (`SUDO_UID`). It only
  connects to a socket whose directory and file belong to that user and aren't accessible to
  anyone else, then proves itself with the token.
- It accepts a fixed set of commands, in lock-step: `create_tun` (MTU and address validated),
  `add_route` (IPv4, host bits zero, never the default route, loopback or multicast),
  `delete_route` (only a route it added),
  `apply_firewall` (rules as intent, not pf text: DNS servers unicast IPv4, ports at least 1024,
  kill switch prefixes IPv4 and not the default route; plus the rules that stay when the tunnel
  goes away, which may only block), `done`, `end` (session: keep the blocking rules or not), and as
  a first command only `adopt` or `cleanup` (rules an earlier session left, below). The platform
  drivers run `/sbin/ifconfig`, `/sbin/route` and `/sbin/pfctl` with fixed argument lists, never a
  shell; the pf rules are rendered by the helper from the validated intent. The utun's file
  descriptor goes back over the socket (SCM_RIGHTS).

### Modes

| | One-shot (routes only) | Session (DNS capture, kill switch, IPv6 block, several profiles) |
|---|---|---|
| sudo prompts | one, at start | one, at start |
| Root process after setup | none: the helper exits | the helper stays up for the session |
| Accepts after setup | nothing | firewall updates (the DNS servers or the local networks changed), route changes (several profiles) and `end` |
| Changing CIDRs | restart subtun | restart subtun (runtime changes with `control: full` are planned) |
| Cleanup | automatic: routes live on the utun, and macOS removes the utun and its routes when subtun exits, crashes or is killed | the same for routes; firewall rules as below |
| Risk | smallest: root exists only for the seconds of setup | a root process stays reachable (only by subtun, over the private socket) for the whole session |

Both modes use the same helper and command loop; session mode just doesn't end it after setup. If
subtun goes away before `done`, the helper removes its firewall rules, the routes it added and the
utun. A one-shot `done` is refused once firewall rules are applied, since nobody would be left to
remove them.

How a session ends:
- **subtun stops deliberately** (Ctrl-C, SIGTERM, terminal closed): it sends `end`. The helper
  removes all firewall rules, except in kill switch `lockdown`, where the blocking rules stay.
- **subtun disappears** (crash, `kill -9`) **or gives up** (tunnel lost, errors) without `end`: the
  helper removes everything without a kill switch; with one (`on` or `lockdown`), the blocking
  rules replace the session's and stay, and pf stays enabled for them.
- **The helper gets a signal itself**: Ctrl-C reaches it as well as subtun, so a signal decides
  nothing by itself: the helper waits a few seconds for subtun's `end` or disconnect, then applies
  the rule above.

**Rules an earlier session left.** The helper records in a root-only file
(`/var/run/subtun/state.json`) which helper holds subtun's rules, pf's enable reference and the
blocking rules meant to stay. When a session finds subtun's anchor in use:
- the recorded helper is still running: another session's rules, left alone; a session that needs
  firewall rules of its own is refused, one that only adds routes goes ahead;
- it is gone: the rules and pf's reference are taken over and replaced by the new session's;
- nothing was recorded: refused, with a pointer to `subtun cleanup`.

Leftovers may block DNS, which subtun needs to resolve its API server. So subtun keeps a marker in
its private run directory while rules may outlive it; when it finds one at the next start, it starts
the helper before connecting and sends `adopt`: blocking rules stay, a DNS block is lifted while
connecting, leftovers that don't block anything are removed. If the start then fails, the
blocking rules are put back. `subtun cleanup` removes leftovers and releases pf without starting a
session, and refuses while a session is running.

## Platform drivers

Everything that differs per operating system goes behind small interfaces, implemented once per OS
and chosen by configuration (with a default per OS). `Tun`, `Routes`, `Firewall` and `DNSCache`
exist (`internal/platform`, macOS drivers in `internal/platform/darwin`: utun, `/sbin/route`, pf,
`dscacheutil` and mDNSResponder); `Resolver` is planned, for the `override` and `supplemental` DNS
modes. The app describes **intent**; each driver translates it into its OS's mechanism, so app code
never contains pf, nftables or route syntax.

```go
// internal/platform: what subtun needs from the OS.
type Tun interface {      // capture interface: macOS utun, Linux TUN, Windows wintun
    Create(mtu int, addr netip.Addr) (TunDevice, error) // TunDevice: Name, File, Release, Close
}
type Routes interface {   // routes on the tunnel interface
    Add(p netip.Prefix, iface string) error
    Delete(p netip.Prefix, iface string) error
}
type Firewall interface { // macOS pf, Linux nftables / iptables, Windows WFP
    Apply(r Rules) error  // atomically replaces subtun's own rules (pf anchor, nft table, ...)
    Flush() error
}
type DNSCache interface { // flushed when DNS capture starts and ends
    Flush() error
}
type Resolver interface { // system DNS configuration: scutil, systemd-resolved, NRPT
    Supplemental(domains []string, server netip.AddrPort) error // only these domains to subtun
    Override(server netip.AddrPort) error                       // subtun as the system resolver
    Restore() error
}

type Rules struct {       // intent, not syntax; fields are added as features need them
    DNS        *DNSRedirect // capture DNS sent to these servers
    DNSBlock   []netip.Addr // block DNS to these servers (kill switch holding)
    KillSwitch *KillSwitch  // block Prefixes unless they leave through TunIface ("" = block all)
    BlockIPv6  bool         // all outgoing IPv6 except link-local, multicast, loopback
}
type DNSRedirect struct {
    Servers    []netip.Addr // queries to these servers (UDP and TCP 53) ...
    ListenPort uint16       // ... go to subtun's listener on 127.0.0.1:ListenPort
    BypassPort uint16       // subtun's own fallback queries leave from here, untouched
}
```

| | macOS (first) | Linux (later) | Windows (later) |
|---|---|---|---|
| Tun | utun (wireguard-go) | TUN (wireguard-go) | wintun (wireguard-go) |
| Routes | `/sbin/route` | netlink | IP helper API |
| Firewall | pf | nftables, iptables as fallback | WFP |
| Resolver | dynamic store (`scutil`) | systemd-resolved (per-link domains) | NRPT |

- Drivers run inside the root helper, because they all need root. The helper protocol carries the
  same intents (`apply_firewall` with `Rules`, `set_resolver`, ...) and validates them; subtun never
  sends raw firewall text, so the helper still accepts only fixed, validated commands.
- Unsupported combinations fail with a clear message. Tests use fake drivers
  (`internal/platform/fake`), so the logic is tested without root on any OS: the helper's command
  loop (setup, undo on disconnect or interrupt, refused commands, driver failures) runs against them.

## DNS

Split DNS by **capturing the system's DNS queries and deciding per name**, as sshuttle `--dns` does
with a regex-pattern patch (`--dns-domains`, `--dns-to`): names matching your domains or patterns go
through the tunnel and are resolved by the target's resolver; everything else goes to a fallback
resolver. Configuration: [DNS](config.md#dns).

```yaml
dns:
  capture: firewall          # firewall (default) | off; override | supplemental planned
  servers: auto              # the system's DNS servers, followed on network change; or a list
  domains: [company.com, azurecr.io]   # suffixes (sshuttle's '.*.x' patterns)
  patterns: ['^db-.*\.prod\..*$']      # optional regular expressions
  fallback: system           # or an address, e.g. 192.168.1.1:53 (the pattern patch's --dns-to)
```

- **DNS engine** (`internal/dns`, OS-independent, runs as the user). Parses each query and matches
  the first question's name. Matches go through the tunnel as a new request type (`CmdDNS`): the
  agent passes the raw message to the resolver in the target's `/etc/resolv.conf`, UDP first and
  TCP if the answer is truncated, and returns the answer unchanged, so every record type works.
  Both agents implement it. The rest goes to the fallback. With `.` (every name), names under
  `local`, the system's search domains and the reverse zones of the local networks and of
  link-local addresses still go to the fallback unless listed: the target's resolver can't answer
  them (against a remote cluster each `.local` query cost a 10 s timeout).
  Errors become SERVFAIL; an answer larger than a UDP client accepts (512 bytes, or its EDNS0 size)
  is replaced by an empty truncated one, so the client retries over TCP, which is captured too.
- **Fallback without loops.** The fallback is usually one of the captured servers, so its queries
  would be redirected straight back. They leave from one fixed source port that the firewall rules
  let through first (TCP connections from the same port, one per server at a time, closed with a
  reset to avoid TIME_WAIT). Each forwarded query gets a fresh ID, and answers from other
  addresses are ignored. (The sshuttle pattern patch set `IP_TTL 42` on its forwarder, but its pf
  rules never check the TTL, so on macOS a `--dns-to` that was also a system server looped.)
- **Answers to queries that went into the utun.** When the DNS server lies inside the routes (a full
  tunnel with a server beyond the LAN, or a corporate DNS server inside a routed range), the app's
  query leaves from the utun's address. pf still redirects it to subtun, but macOS sends subtun's
  answer to that address out of the utun, since the address is also the point-to-point peer. The
  stack hands packets for the utun's own address straight back to the system, so the answer
  reaches the app. Fallback queries to such a server still fail: they are UDP into the utun, which
  carries TCP only so far.
- **Answers outside the routes** (`dns.unrouted`). A tunnel answer with private addresses no route
  covers (a remote cluster's resolver answered `github.com` with `100.64.0.0/10`) is kept with a
  warning (`warn`, default), replaced by the fallback's answer (`fallback`), or rewritten without
  those A records (`block`). Planned: `tunnel`, routing such addresses into the utun for the session
  (builds on the session helper's route changes), and `auto`, which would start as `tunnel` and
  fall back to the normal path when replies don't come.
- **DNS cache.** The helper flushes the system's DNS cache (a `DNSCache` driver; macOS:
  `dscacheutil -flushcache` and SIGHUP to mDNSResponder) whenever the DNS redirect goes on or off,
  and when it takes over or cleans up an earlier session's rules. Otherwise answers from before the
  capture bypass it for their TTL, and, after it, answers obtained through the tunnel point at
  addresses only reachable through it (a name kept failing for its TTL after subtun stopped).
- **How queries reach it** is a driver choice:

| `capture` | Mechanism | Notes |
|---|---|---|
| `firewall` (default, implemented) | the firewall driver redirects DNS (UDP/TCP 53) sent to the DNS servers into subtun, like sshuttle's pf `rdr` | matches by port, so a DNS server that is also the default gateway (most home routers) works; data never goes through pf |
| `override` (planned) | the resolver driver makes subtun the system resolver while it runs | no firewall; interplay with other VPN clients' DNS to test |
| `supplemental` (planned) | the resolver driver sends only the listed suffixes to subtun | smallest footprint; suffixes only at the OS level |
| — | routing the DNS server's IP into the utun | rejected: at home the DNS server is usually the default gateway, and a route for it would capture all traffic |

- **pf rules** (macOS), in subtun's own anchor `com.apple/subtun`, which the stock `/etc/pf.conf`
  evaluates, so the main ruleset is never modified:

  ```
  table <subtun_dns> const { 192.168.1.1 }
  rdr pass on lo0 inet proto { udp tcp } from any to <subtun_dns> port 53 -> 127.0.0.1 port <listen>
  pass out quick inet proto { udp tcp } from any port <bypass> to <subtun_dns> port 53 keep state
  pass out quick route-to lo0 inet proto { udp tcp } from any to <subtun_dns> port 53 keep state
  ```

  Every filter rule is `quick`, so other software's anchors can't override them (sshuttle#1253).
  The driver refuses to run if its anchor already holds rules (another subtun, or leftovers from a
  killed helper), if the main ruleset doesn't evaluate `com.apple/*` or if pf skips `lo0`
  (sshuttle replaces the main ruleset in that case), warns when other anchors exist, enables pf
  with a reference token (`pfctl -E`) and releases it (`-X`), so pf ends up as it was. It flushes
  only its anchor's rules, NAT rules and tables: `pfctl -a <anchor> -F all` would also clear pf's
  global state table.
- With `servers: auto` the captured servers come from `/etc/resolv.conf` (IPv4; IPv6 and local
  servers are reported) and are re-read every few seconds; when they change, the helper replaces
  the rules.
- One entry covers any number of domains; no file per domain.

## Kill switch and full tunnel

Configuration: [Kill switch](config.md#kill-switch), [IPv6](config.md#ipv6).

- **Full tunnel** works through route planning: route `0.0.0.0/1` and `128.0.0.0/1`. The real
  default route stays untouched, the LAN stays local and subtun's own connection is excluded. DNS
  follows with `dns.domains: ["."]`. The target must be outside this machine (see
  [Routing loops](#architecture)), and UDP and ICMP to the internet don't pass, since the utun
  carries TCP only so far.
- **Kill switch** (`killSwitch.mode: on | lockdown`): if subtun dies, its routes vanish with the
  utun, and that traffic would fall back to the normal default route: a leak. pf rules allow traffic
  to the guarded prefixes only through subtun's utun, and when the tunnel goes away, block rules
  stay (fail-closed) until the next session takes them over or `subtun cleanup` removes them. `on`
  releases them when you stop subtun; `lockdown` keeps them then too. Both are configurable
  globally (`defaults`) and per profile, since which one is right depends on the use case.
- **Guarded prefixes** are computed with the route planner: the routes minus local interface
  networks that are more specific (most specific wins, as in the routing table). The LAN in a full
  tunnel stays reachable; a route more specific than a VPN client's network stays guarded. They
  follow the machine's networks: checked every 5 s, and when they change the whole rule set
  (running and kept) is sent again, so another Wi-Fi's LAN, router and DHCP aren't blocked.
- **DNS while blocked** (`killSwitch.dns`): pf can't block by name, so the choice is all DNS to the
  captured servers (`block`, default: no name leaks, and no private-link name resolving to a public
  endpoint) or none (`allow`). The blocking rule replaces the redirect, rather than leaving a
  redirect to a port nobody listens on, which any local process could then bind.
- **IPv6** (`blockIPv6: auto | true | false`): all outgoing IPv6 except link-local, multicast and
  loopback, `block return` so apps fall back to IPv4 at once. `auto` blocks it in a full tunnel only.
  Skipped, with a warning, when subtun's own connection may use IPv6.

```
table <subtun_guard> const { 0.0.0.0/1 128.0.0.0/2 ... }
pass out quick on utun10 inet from any to <subtun_guard>        # while running
block return out quick inet from any to <subtun_guard>
pass out quick on lo0 inet6 all                                  # IPv6 block
pass out quick inet6 from any to { fe80::/10, ff00::/8 }
block return out quick inet6 all
```

DNS rules come before the kill switch, so a captured DNS server inside the guarded prefixes is still
captured. What stays behind has no `pass` rule and blocks DNS with
`block return out quick inet proto { udp tcp } from any to <subtun_dns> port 53`.

## Several tunnels

One subtun process runs several profiles at once, each with its own target: split routing to
several remotes, for example `10.0.0.0/8` and `corp.example` through a work cluster,
`10.50.0.0/16` and `cluster.local` through a dev cluster.

```
subtun up work                            # one profile, as today
subtun up --profile work,dev              # several
subtun up --profile work --profile dev    # the same
```

**Why one process.** Running `subtun up work` and `subtun up dev` side by side only works for
routes. Both want the same utun address. Only one session can own the firewall anchor, so the
second one's DNS capture or kill switch is refused. Only one DNS engine can answer the captured
servers. And two kill switches can't be combined.

```
app ──► utun + gVisor ──► router ──┬─► tunnel work ══► agent in the work pod
        (every profile's routes)   └─► tunnel dev  ══► agent in the dev pod
system DNS ──► DNS engine ─────────── per name: work, dev or the fallback
app ──► SOCKS (one per profile) ───── its own tunnel only
```

- **Shared:** one utun, one root helper, one firewall rule set, one DNS engine. The utun carries
  the routes of the profiles that are running. The root side gains one thing: route changes
  during a session (see Starting and failing).
- **Connections:** of the profiles whose own routes (after their own excludes) cover the
  destination, the one whose configured route containing it is most specific carries it, the
  rule routes and excludes already follow within a profile. The address space is split into
  prefixes, each carried by one profile; the stack's dialer becomes a router over them, and the
  kill switch's guard and `dns.unrouted` use the same split. The stack, the loop guard and the
  hand-back stay as they are.
- **DNS:** a name goes to the tunnel with the most specific matching domain (`db.corp.example`
  goes to the profile listing `corp.example`, not to one listing `example`); then to the first
  matching pattern, in profile order; then to the profile with `.`, if any (local names still
  stay local); else to the fallback. `dns.unrouted` checks a tunnel's answers against the
  addresses that tunnel carries, since a connection to an address another tunnel carries would
  go there. The targets' own endpoint names never go through a tunnel, so a tunnel that is down
  can still look up its API server.
- **Per tunnel:** target, agent, agent directory, SOCKS proxy (it dials only its own tunnel, and
  hostnames resolve on that agent), reconnect, `dns.unrouted`, the warning about a target on this
  machine, its state, and later its counters. Log lines carry `tunnel=<profile>`.
- **Kill switch per profile:** the guard covers the routes of the profiles with a kill switch,
  minus the parts a more specific route of a profile without one takes over, minus the local
  networks. `on` and `lockdown` can differ: on a deliberate stop subtun first narrows the rules
  that stay to the `lockdown` profiles' share, then ends the session.
- **Shared settings** exist once, so values the profiles set are merged:
  - `killSwitch.dns`: `block` if any profile with a kill switch asks for it;
  - `blockIPv6`: blocked if any profile's setting blocks it (`auto` in a full-tunnel profile);
  - `dns.servers`: the union (`auto`: the system's servers, followed);
  - `dns.capture`: runs if any profile with DNS names wants it; a profile with `off` adds no names;
  - `dns.fallback`, `tun.address` and `tun.mtu` have no sensible merge: different values are an
    error, to be fixed in `defaults:`.

  A profile that doesn't set a value has no say.

**Combining profiles:**
- The same CIDR in the routes of two profiles is an error, and so are the same DNS domain, `.` in
  more than one profile, and the same SOCKS address.
- Overlapping routes follow most specific wins: dev's `10.50.0.0/16` takes those addresses from
  work's `10.0.0.0/8`. The dry run lists each profile's routes and notes the parts another
  profile carries.
- A full tunnel in one profile carries whatever the others don't route.
- A profile's excludes apply to its own routes: work's `10.50.0.0/16` exclude doesn't stop dev
  from routing it, and an address dev excludes goes to work if work routes it. Excludes in
  `defaults:` apply to every profile.
- The automatic excludes apply to each profile as today. Every tunnel's own endpoints (API
  servers, Docker daemons) are excluded from every route, so no tunnel's connection runs inside
  another tunnel. They come from the kubeconfig or docker context, so they are known before a
  tunnel connects; they are looked up after rules an earlier session left (which may block DNS)
  are taken over, and a failed lookup is reported.
- Later: a priority for a CIDR or domain listed in two profiles, and with it failover (the same
  CIDR through two remotes, the second used while the first is down). Until then both are errors
  at start.

**Command line:**
- The profiles are `up`'s argument plus every `--profile` (repeatable or comma-separated); with
  `--profile`, no argument is needed. Profile names and CIDRs never mix as arguments: a bare IP
  like `10.1.2.3` is also a valid profile name.
- Several profiles are configured in the config file only: the command line then takes run
  options (`--dry-run`, `-v`, `--config`) and nothing else. CIDRs and setting flags work when one
  profile starts, as today.
- `subtun k8s`, `subtun docker` and a single profile keep their sequence: connect, then sudo, and
  a one-shot helper unless firewall rules need a session.
- No new config keys. A name for a combination of profiles in the config can come later if typing
  the list turns out to be tedious.

**Starting and failing:**
- A profile behaves as if it ran alone. Its routes are on the utun while its tunnel is up or
  reconnecting: added when it first connects, removed when it gives up. Its traffic then takes
  the normal path, or a broader route of another profile, and its DNS names go to the next match
  or the fallback.
- A profile with a kill switch puts its routes in at start and keeps them when it gives up: its
  traffic is refused rather than leaking, and if subtun exits, the guard holds.
- All tunnels try to connect once, in parallel, before the capture starts, as a single profile
  does (connect, then sudo): a first connection never depends on DNS or routes through a tunnel
  that is down. The capture then starts (after 30 s at most; a profile still connecting carries
  on) with the routes of the profiles that are up and of those with a kill switch; one that
  couldn't connect retries by its reconnect policy. The capture starts off the event loop, so
  tunnels keep reconnecting while sudo asks.
- Each tunnel reconnects on its own. While one is down, only its destinations get resets and only
  its names SERVFAIL; the others carry on.
- subtun exits on Ctrl-C, or when every profile has given up. A profile giving up is logged, and
  later shown by `subtun status`.
- A route that can't be added (another VPN client holds it) doesn't hold up the others; the
  update is retried, less often while the same error repeats, and a profile's names only switch
  on once all its routes are in.
- **Route changes during a session.** With several profiles the root helper always stays up for
  the session and accepts `add_route` and `delete_route` after setup (only for routes it added,
  validated like the first ones). subtun computes the whole route set for the profiles running
  and sends the difference, additions before removals, so no address falls out of the tunnel
  in between. A tunnel connecting later whose endpoint lies inside the routes gets the covering
  route replaced by pieces around it the same way. A single-profile run keeps the one-shot helper.

**Overlapping address spaces.** Connections are split by destination address, so two remotes
using the same addresses (two clusters with the default `10.96.0.0/12` service range) can't both
be routed: the same CIDR twice is an error. Their SOCKS proxies still work, each through its own
tunnel. Possible later: DNS answers from one tunnel get addresses from a private pool, which
subtun maps back to the real ones (fake-IP style).

**Status and control:** see [Status and control](#status-and-control-planned). Runtime changes
build on the route changes above.

**Rejected:**
- One process per profile: see "Why one process" above.
- One utun per tunnel, chosen by the system's routes: the routing table would show which tunnel
  carries what, but the helper would need several utuns, and the kill switch rules per interface,
  for a choice the process can make itself.
- `subtun up work dev` with several profile names as arguments: they can't be told apart from
  CIDRs reliably (see Command line).

## Status and control (planned)

Not built yet. A running subtun answers questions about itself (`subtun status`, `subtun logs`),
and on request accepts changes (routes, DNS names, profiles) without a restart. Everything is
shaped as a list of tunnels: one in a single-profile run, several with `--profile a,b`.

**Where it lives.** In the subtun process, which runs as the user; never in the root helper.

- One Unix socket per running subtun, `control-<pid>.sock` in the private run directory
  (`~/Library/Caches/subtun/run`, 0700; socket 0600). The peer's uid is checked as well (macOS
  `LOCAL_PEERCRED`). `subtun status` finds every running subtun by its socket and removes sockets
  whose process is gone.
- JSON over HTTP on that socket, under `/v1/`, so `curl --unix-socket` works too. Live updates
  (state changes, counters, log lines) come as newline-delimited JSON on one long response
  (`/v1/events`); a WebSocket comes with the web UI.
- Later, for a browser UI: an optional localhost TCP listener with a random token (Jupyter style).

**What it reports:**

- **The run:** pid, version, start time, the utun and its address, the root helper (one-shot or
  session), the control mode.
- **Each tunnel (profile):**
  - target, agent (binary or Python, version), state and since when (connecting, up,
    reconnecting with attempt n of m and the next try, gave up) and the last error;
  - its routes on the utun, and the parts another profile carries; its DNS domains and patterns;
    its SOCKS address; its kill switch mode;
  - counters: connections open, total and failed (through the utun and through SOCKS), bytes up and
    down, rates (1 s samples, the last 5 minutes kept), DNS queries answered through it and failed,
    loop-guard refusals.
- **Shared:** the captured DNS servers and the fallback, the names that stay local, subtun's own
  endpoint names; queries answered by the fallback; the kill switch (guarded and lockdown prefix
  counts) and the IPv6 block.
- **Connections** (on request): one row per open connection: destination, profile, utun or SOCKS,
  bytes each way, age.
- **Logs:** an in-memory ring buffer (5000 lines and 4 MB at most), fed by an extra log handler;
  never written to disk. Slow readers lose lines; the tunnel never waits for them.

**Commands:**

```
subtun status [--json] [--pid N]       # every running subtun, or one
subtun status --watch                  # refreshed every second (a terminal UI comes later)
subtun status --connections            # with the open connections
subtun logs [-f] [--pid N]             # the ring buffer, then follow
```

With `control: full` also (each change planned and checked as at start: conflicts, safety checks,
the endpoints; `--dry-run` shows the effect):

```
subtun route add|del [--profile P] CIDR...     # a profile's routes
subtun dns add|del [--profile P] DOMAIN...     # a profile's DNS domains
subtun profile reconnect|stop|start NAME       # start: from the config file, next to the others
```

Changes are temporary: they last until subtun stops, and nothing is written back to the config
file (saving them is a possible later feature).

**Setting:** global for the run, never per profile: `--control`, or a top-level `control:` key in
the config file (next to `defaults:` and `profiles:`).

| Mode | What | Root |
|---|---|---|
| `status` (default) | status, connections and logs, read only | nothing changes: a routes-only run keeps its one-shot helper |
| `full` | also the changes above | the root helper stays up for the session, as with several profiles |
| `off` | no socket | |

`full` is opt-in. With it, any process of the same user can change routes during the session
without a sudo prompt. The routes can only point into subtun's utun, and the helper validates each
one, but the user should choose that.

**One engine first.** A single profile and several profiles run through two different loops
today, so status, counters and control would have to be built twice. Single-profile runs (`subtun
up NAME`, `subtun k8s`, `subtun docker`) move onto the several-profile engine with one profile and
keep their behaviour:
- connect, then sudo;
- a first connection that fails exits at once;
- a one-shot helper unless firewall rules or `control: full` need a session;
- giving up exits.

This is a refactor without behaviour changes, root-tested again on the test machine before
anything builds on it.

**Built on it later** (not part of this):
- `dns.unrouted: tunnel` and `auto`;
- routes that follow network changes (the automatic local excludes recomputed);
- reconnecting to a recreated pod by label or owner;
- a terminal UI and an embedded web UI;
- saving runtime changes back to the config file.

**Order:**
1. One engine (refactor) and its root test.
2. Status: the socket, counters, connections, logs, `subtun status` and `subtun logs`.
3. Control: `control: full` and the changes.

## Decisions

- **Capture:** utun / TUN interface plus the gVisor network stack, with utun MTU 9000. Data never
  goes through pf; the firewall (pf, nftables, WFP) is only used for DNS capture, the kill switch and
  blocking IPv6, through a firewall driver.
- **OS-specific code behind drivers** (tun, routes, firewall, resolver), chosen by configuration.
- **Remote side:** an agent over exec stdio, not SSH `direct-tcpip`. Containers rarely run sshd,
  and UDP, remote DNS and host discovery need an agent anyway. The Go binary by default, the
  Python edition where the binary can't run.
- **Agent location:** never a shared, world-writable path. Per-user 0700 directories, `$HOME` first.
- **DNS:** capture the system's queries (firewall redirect by default) and decide per name in
  subtun: domains and patterns through the tunnel, the rest to a fallback. Supplemental and override
  modes as resolver drivers. Not one file per domain.
- **Every setting works from the command line** and from the YAML config.
- **Privileges:** the tool runs as the user; root only in the helper, one-shot by default, session
  mode when firewall rules are needed (see Privileges).
- **Fail-open by default, fail-closed on request:** without a kill switch every firewall rule goes
  when subtun goes; with one, blocking rules stay until taken over or cleaned up.
- **Global defaults** in the config file for every setting; a profile's own value wins.
- **Pure Go:** `CGO_ENABLED=0`, a single static binary per OS and architecture.

## Open questions

- **Routes don't follow network changes** (the kill switch's guard does: it's recomputed when the
  local networks change, every 5 s). The automatic excludes for local networks are computed at
  start: after joining another network, the old LAN's range stays outside the tunnel, and an
  exclude that splits the routes inside the new LAN would put parts of it into the tunnel. Needs
  runtime route changes in the session helper.
- **Reconnecting to a recreated pod:** subtun reconnects to the same pod name. A Deployment's new pod
  has another name; selecting the target by label or by its owner would find it. Also, routes
  don't change while running, so if the API server's address moves inside the routes after a
  reconnect, subtun only warns (restart to exclude it).
- **Targets with neither a shell nor Python** (distroless static, scratch): an ephemeral debug
  container (Kubernetes) or a helper container in the target's network namespace (Docker).
- **Aborted streams:** smux has no reset. When the laptop side closes a stream abruptly, an agent
  still sending to it waits for window updates that never come, until the destination closes.
  Both agents behave the same; needs a reset signal in the protocol.
- **Remote clusters:** one has been measured so far: a single arm64 node on the same LAN, through its
  pod's own internet connection. A full tunnel reached about 20 MB/s down and 8-9 MB/s up, against
  53 and 38 MB/s directly (SOCKS through the same pod: 20 MB/s down). Where that limit sits (the
  node, its uplink, exec through the API server, smux) isn't known yet; transport flow control
  (several carriers in parallel against head-of-line blocking) waits for that answer.
- **Coexistence** with other VPN or security software that owns its own utun interface or pf anchor
  (pf driver: own anchor, `quick` rules, warn on other anchors; to be tested next to Zscaler).
- **A helper killed with SIGKILL** leaves its running rules, including the DNS redirect to subtun's
  listener port. Until the next session takes them over or `subtun cleanup` runs, a local process
  could bind that port and answer the Mac's DNS queries.
- **Loop guard limits:** the caps (64 opening, 256 open per destination) aren't configurable. A
  client opening more connections to one address and port at once would be refused for 10 s.
  Targets in a VM on a bridge network (an address on a local network rather than loopback) don't
  trigger the start warning; only the caps catch their loops.
- **Reconnecting through a full tunnel** while the tunnel is down: a kubeconfig whose
  credentials come from an exec plugin (a cloud login) needs the internet, which the full
  tunnel's routes send into the tunnel that is down. The first connection is made before the
  capture starts; a reconnect that needs the plugin again can't reach its login service.
- **IPv6 DNS servers** are not captured yet (IPv4 only, like sshuttle with `--disable-ipv6`).
- **UDP through the tunnel:** a fallback resolver inside a routed CIDR fails, because the utun
  carries TCP only so far.
- **Docker transport upload** is ~25 % below Kubernetes on the same Mac (147 vs 193 MB/s through
  utun). Candidate: one write per smux frame straight onto the hijacked Docker connection, where
  the Kubernetes path batches through client-go.
