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
  it terminates TCP connections and UDP flows to any routed destination. Each connection is dialed
  through the tunnel *before* the handshake with the local app completes: an unreachable
  destination gets a TCP reset, as on a real network. TCP settings follow tun2socks (SACK, RACK, no
  Nagle delay). A UDP flow (the app's address and port to one destination) gets its endpoint at its
  first datagram (a 4 MiB receive buffer), which waits there while the flow is dialed (`CmdUDP`: one
  stream, datagrams framed by a 16-bit length both ways). The agent sends from a connected socket
  of its own (asking for a 4 MiB receive buffer; Linux caps it at `net.core.rmem_max`). The Go
  agent drains that socket into a queue of up to 4 MiB (full: the datagram is dropped and counted)
  and a writer feeds the stream from it, so a busy stream doesn't overflow the socket; the Python
  agent takes what the socket holds at each wake-up and writes it into the stream at once (a writer
  thread costs Python more than it saves: it lost more at high rates). Several datagrams can share
  a stream write; the framing keeps them apart. An error for one
  datagram doesn't end a flow, on either side: the ICMP errors a connected socket reports (port,
  host or network unreachable, too big for the path; gVisor reports a port unreachable from the
  app's side on the next read) are counted, and the first of each kind is logged at debug; 1000
  read errors in a row with no datagram between them do end it. A flow closes after 2 minutes
  without a datagram either way (15 s for port 53). Both sides log at debug why a flow ended
  (`reason`), with its errors and drops. The loop guard counts UDP flows apart from TCP
  connections. ICMP isn't carried.
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
  connect time the API server, Docker daemon or SSH server address is excluded automatically. Details:
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

- subtun creates a unix socket in a private directory (`~/.local/state/subtun/run`, or `$XDG_RUNTIME_DIR/subtun` when set; mode 0700,
  socket 0600) and starts `/usr/bin/sudo -- <subtun> helper --socket <path>`, passing a random
  token on the helper's stdin.
- The helper refuses to run unless it is root and started through sudo (`SUDO_UID`). It only
  connects to a socket whose directory and file belong to that user and aren't accessible to
  anyone else, then proves itself with the token.
- It accepts a fixed set of commands, in lock-step: `create_tun` (MTU and address validated),
  `add_route` (IPv4, host bits zero, never the default route, loopback or multicast),
  `delete_route` (only a route it added), `flush_dns_cache` (only while DNS is redirected),
  `apply_firewall` (rules as intent, not pf text: DNS servers unicast IPv4, ports at least 1024,
  kill switch prefixes IPv4 and not the default route; plus the rules that stay when the tunnel
  goes away, which may only block), `clear_firewall` (session: remove its own rules when none is
  needed any more, e.g. every kill switch profile stopped), `done`, `end` (session: keep the
  blocking rules or not), and as
  a first command only `adopt` or `cleanup` (rules an earlier session left, below). The platform
  drivers run `/sbin/ifconfig`, `/sbin/route` and `/sbin/pfctl` with fixed argument lists, never a
  shell; the pf rules are rendered by the helper from the validated intent. The utun's file
  descriptor goes back over the socket (SCM_RIGHTS).

### Modes

| | One-shot (routes only) | Session (DNS capture, kill switch, IPv6 block, several profiles) |
|---|---|---|
| sudo prompts | one, at start | one, at start |
| Root process after setup | none: the helper exits | the helper stays up for the session |
| Accepts after setup | nothing | firewall updates (the DNS servers or the local networks changed) or their removal, route changes (several profiles, `control: full`), DNS cache flushes and `end` |
| Changing CIDRs | restart subtun (`control: full` keeps the helper up: a session) | `subtun route add\|del` with `control: full` |
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
exist (`internal/platform`; macOS drivers in `internal/platform/darwin`: utun, `/sbin/route`, pf,
`dscacheutil` and mDNSResponder; Linux drivers in `internal/platform/linux`, see [Linux](#linux));
`Resolver` is planned, for the `override` and `supplemental` DNS modes. The app describes **intent**; each driver translates it into its OS's mechanism, so app code
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

| | macOS | Linux (Debian, Ubuntu) | Windows (later) |
|---|---|---|---|
| Tun | utun (wireguard-go) | TUN, plain IP packets, no address | wintun (wireguard-go) |
| Routes | `/sbin/route` | `ip`, subtun's own table + two rules | IP helper API |
| Firewall | pf | nftables (next) | WFP |
| DNS cache | `dscacheutil`, mDNSResponder | `resolvectl flush-caches` (next) | |
| Resolver | dynamic store (`scutil`) | systemd-resolved (per-link domains) | NRPT |

- Drivers run inside the root helper, because they all need root. The helper protocol carries the
  same intents (`apply_firewall` with `Rules`, `set_resolver`, ...) and validates them; subtun never
  sends raw firewall text, so the helper still accepts only fixed, validated commands.
- Unsupported combinations fail with a clear message. Tests use fake drivers
  (`internal/platform/fake`), so the logic is tested without root on any OS: the helper's command
  loop (setup, undo on disconnect or interrupt, refused commands, driver failures) runs against them.

### Linux

Debian and Ubuntu first; other distributions may well work (they need `ip` from iproute2), and
subtun can run in a container where they don't.

- **Commands** (`ip`, `sudo`, later `nft` and `resolvectl`) are found by `internal/syscmd` in fixed
  system directories (`/usr/sbin`, `/sbin`, `/usr/bin`, `/bin`, `/usr/local/sbin`, `/usr/local/bin`),
  never through `$PATH` (the helper runs them as root), and run only if root owns the file and its
  directory and nobody else can write either. Fixed argument lists, no shell, as on macOS.
- **The TUN interface** (`subtunN`, picked by the kernel) carries plain IP packets: no packet
  information header, no offloads. It gets **no address**: routes into it don't need one, and
  connections through it use one of the machine's own addresses, to which the answers come back
  (the netstack accepts any source). A new address makes other software react: microk8s's
  apiserver-kicker added it to the API server certificate and restarted the API server, twice (when
  it came and when it went), and mDNS responders announce addresses. IPv6 is switched off on it.
  The interface isn't persistent: it goes, with its routes, when subtun's descriptor closes.
- **Routes live in a table of subtun's own** (32761), and two rules send *this machine's own*
  traffic (`iif lo`) there, right before `main` (32766), after any other policy rules (VPNs,
  Cilium):
  ```
  32760: from all iif lo lookup main suppress_prefixlength 0   # main's specific routes first
  32761: from all iif lo lookup 32761                          # then subtun's routes
  32766: from all lookup main                                  # then main's default route
  ```
  - Traffic the machine forwards (containers, pods, VMs on a bridge) never uses subtun's routes. On
    Linux a container's traffic goes through the host's routing: with subtun's routes in `main`, a
    target on this machine (a local cluster, a Docker container) would send its connections to
    routed addresses back into the tunnel. With these rules it doesn't, so no local-loop warning
    at start on Linux (the loop guard still catches the rarer cases: an SSH target that is this
    machine, userspace container networking).
  - `main`'s specific routes win over subtun's: the LAN, container and pod networks and other VPNs'
    routes keep working, also in a full tunnel. Unlike macOS (one table, the most specific route
    wins), a route of subtun's inside a broader non-default route in `main` loses to it.
  - The reverse-path check (`rp_filter`) looks the source up as if it came from `lo`, so answers
    arriving on the TUN pass even with strict filtering.
  - The rules don't go away with the interface (routes do), so on Linux the root helper always
    stays up for the session and removes them when subtun stops, goes away or is killed
    (`platform.RouteTable`: `Setup`, `Teardown`, `InUse`). If both are killed, the next start
    replaces the rules and `subtun cleanup` removes them; neither touches them while a subtun
    interface exists (a running session). Rules at those priorities that aren't subtun's are
    refused, never removed.
- **Not yet on Linux:** the firewall features (DNS capture, the kill switch, the IPv6 block; a full
  tunnel turns the IPv6 block on by itself, so for now it needs `--block-ipv6 false`), the DNS cache
  flush, and per-link DNS through systemd-resolved (distributions whose resolver library talks to
  resolved directly instead of sending queries to 127.0.0.53 need it for DNS capture).
- `--tun-addr` only matters on macOS.

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
  reaches the app. Fallback queries to such a server go through the tunnel as UDP, so they work
  too.
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
  During a session subtun asks for a flush (`flush_dns_cache`) when a tunnel with DNS names comes
  back after an outage (a lookup that failed while it was down kept failing for a moment after
  the reconnect), and when a profile's names start or stop going through a tunnel.
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
  [Routing loops](#architecture)). TCP and UDP to the internet go through the tunnel; ICMP doesn't.
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
  servers, Docker daemons, SSH servers or their first jump host) are excluded from every route, so no tunnel's connection runs inside
  another tunnel. They come from the kubeconfig, docker context or `ssh -G`, so they are known before a
  tunnel connects; they are looked up after rules an earlier session left (which may block DNS)
  are taken over, and a failed lookup is reported.
- Later: a priority for a CIDR or domain listed in two profiles, and with it failover (the same
  CIDR through two remotes, the second used while the first is down). Until then both are errors
  at start. (A design for this, with deciding per destination inside subtun, is being discussed:
  [Planned](../README.md#planned).)

**Command line:**
- The profiles are `up`'s argument plus every `--profile` (repeatable or comma-separated); with
  `--profile`, no argument is needed. Profile names and CIDRs never mix as arguments: a bare IP
  like `10.1.2.3` is also a valid profile name.
- Several profiles are configured in the config file only: the command line then takes run
  options (`--dry-run`, `-v`, `--config`) and nothing else. CIDRs and setting flags work when one
  profile starts, as today.
- A target given on the command line and a single profile keep their sequence: connect, then
  sudo, and a one-shot helper unless firewall rules need a session.
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

**Status and control:** see [Status and control](#status-and-control). Changes while running
build on the route changes above.

**Rejected:**
- One process per profile: see "Why one process" above.
- One utun per tunnel, chosen by the system's routes: the routing table would show which tunnel
  carries what, but the helper would need several utuns, and the kill switch rules per interface,
  for a choice the process can make itself.
- `subtun up work dev` with several profile names as arguments: they can't be told apart from
  CIDRs reliably (see Command line).

## Status and control

Both are built. A running subtun answers
questions about itself (`subtun status`, `subtun logs`), and on request accepts changes (routes, DNS
names, profiles) without a restart. Everything is
shaped as a list of tunnels: one in a single-profile run, several with `--profile a,b`.

**Where it lives.** In the subtun process, which runs as the user; never in the root helper.

- One Unix socket per running subtun, `control-<pid>.sock` in the private run directory
  (`~/.local/state/subtun/run`, or `$XDG_RUNTIME_DIR/subtun`; 0700; socket 0600). The peer's uid is checked as well (macOS
  `LOCAL_PEERCRED`). `subtun status` finds every running subtun by its socket and removes sockets
  whose process is gone.
- JSON over HTTP on that socket, under `/v1/`, so `curl --unix-socket` works too: `/v1/status`,
  `/v1/connections`, `/v1/samples` (each tunnel's 1 s traffic samples, the last 5 minutes),
  `/v1/config` (the profiles of the run's config file, read when asked, and which are in the
  run), and `/v1/logs` (newline-delimited JSON, each line with its level and profile; with
  `?follow=1` new lines keep coming); with `control: full` also `POST /v1/routes`, `/v1/dns`,
  `/v1/profiles` and `/v1/log` (a JSON change: `op`, `profile`, `cidrs` and `exclude`, `domains` and
  `patterns`, `reload`, `level`, `dryRun`), answered
  with what changed, or refused with the reason (403 when read only). A general event stream (state changes and counters as they happen) and a WebSocket
  come with the web UI; `subtun status --watch` and the terminal UI poll once a second meanwhile.
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
  the log file (below) is separate. Slow readers lose lines; the tunnel never waits for them.
- **Log files** (added later, for long runs and a daemon to come): one JSON file per start in
  `~/.local/state/subtun/logs` (nix style: subtun is a command-line tool), rotated by size, pruned
  by age (3 days) and total size; levels per component through a `component` attribute every part
  logs with; optional masking of DNS names and destinations (keyed hashes, a new key per run). Global
  for the run, like `control`. Masking is optional because full logs are what an investigation
  needs.

**Commands:**

```
subtun status [--json] [--pid N]       # every running subtun, or one
subtun status --watch                  # refreshed every second (or subtun tui)
subtun status --connections            # with the open connections
subtun logs [-f] [--pid N]             # the ring buffer, then follow
```

With `control: full` also (each change planned and checked as at start: conflicts, safety checks,
the endpoints; `--dry-run` shows the effect):

```
subtun route add|del [--profile P] [-x] CIDR...                # a profile's routes (-x: excludes)
subtun dns add|del [--profile P] [DOMAIN...] [--pattern RE]... # a profile's DNS names
subtun profile stop|start|reconnect [NAME] [--reload]          # one profile; the others go on
                                                               # (start NAME not in the run: add it)
```

Changes are temporary: they last until subtun stops, and nothing is written back to the config
file (saving them is a possible later feature). `--profile` (and `NAME`) can be left out when the
run has one profile.

**How the engine makes them.** The engine's loop owns the plan; changes reach it from the control
socket and are made one at a time, between tunnel events. Each is planned with the functions used at
start (`planRoutes`, the endpoint carve, the overlap check, the DNS matcher's rules) and only then
applied; the loop then brings the router, the DNS matcher and the capture (`Capture.Update`) in line,
as when a tunnel comes or goes. Each profile's tunnel runs in its own goroutine (a runner); stop,
start and reconnect replace it, the new one waiting for the old one to finish, and events from a
replaced runner are ignored. Changes to the plan are refused while the capture is starting (sudo may
be asking).

**Decisions** (with the user, 2026-11-13):
- `profile stop` is Ctrl-C for that profile: `killSwitch.mode: on` lifts its blocks, `lockdown`
  keeps its share blocked until it starts again (or subtun ends: then as lockdown always does). A
  stopped profile is not a given-up one: subtun goes on while profiles are stopped.
- `profile start` brings a profile back as it was when stopped (its start-up settings plus the
  changes since); `--reload` reads it from the config file the run started with instead, and drops
  the changes. The settings the run shares or set up at start can't change by a reload (refused,
  restart instead): `tun.*`, `dns.capture`, `dns.servers`, `dns.fallback`, `dns.unrouted`,
  `killSwitch.*`, `blockIPv6`.
- `dns add` takes domains and, with `--pattern`, regular expressions, as `dns.domains` and
  `dns.patterns`.
- Limits for now: routes only for a profile that started with routes, at least one left; DNS names
  only when the run captures DNS already, and only for a profile whose DNS servers it captures
  (starting DNS capture, the firewall, or capturing other servers later in a run isn't done).
- Exit as before: subtun ends when every profile has given up (one profile: when it gives up), also
  right after a start or reconnect that failed; stopped profiles keep it running.

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

**One engine** (done first). Single-profile runs (`subtun up NAME`, or a target given with `--k8s`
or `--docker`) run on the several-profile engine with one profile, so status, counters and control
are built once. They keep their behaviour:
- connect, then sudo;
- a first connection that fails exits at once;
- a one-shot helper unless firewall rules or `control: full` need a session;
- giving up exits.

**Built on it later** (not part of this):
- `dns.unrouted: tunnel` and `auto`;
- routes that follow network changes (the automatic local excludes recomputed);
- reconnecting to a recreated pod by label or owner (done: [Targets](#targets));
- an embedded web UI (the terminal UI is built: below);
- saving runtime changes back to the config file.

**Order:**
1. One engine (refactor) and its root test. Done.
2. Status: the socket, counters, connections, logs, `subtun status` and `subtun logs`. Done.
3. Control: `control: full` and the changes to the run's profiles. Done.
4. Starting a profile that isn't part of the run (`profile start NAME` from the config file, next to
   the others). Done: the engine's per-profile tables grow while running (the plan and the status
   under `mp.smu`, runners, SOCKS listeners, the DNS engine's tunnels via `Engine.AddTunnel`, the
   matcher's targets, which start switched off); the profile is planned with the config's settings
   only, against the run (`planAdd`). A profile with routes needs a run with a capture, one with a
   kill switch a capture with a guard; DNS names are ignored without the run's DNS capture and
   refused for servers it doesn't capture; `killSwitch.dns` and a full tunnel's IPv6 block only warn
   once the capture runs. Not for runs whose tunnel has no profile name (a target given with `--k8s`
   or `--docker`).

## Terminal UI

`subtun tui` is a client of the control socket, like `subtun status`: it attaches to a running
subtun from another terminal, and quitting it leaves subtun running. It shows everything status
does, the log lines, a sparkline per profile from `/v1/samples`, and with `control: full` makes the
same changes as `subtun route|dns|profile`, each after its dry run. It polls the status once a
second and follows `/v1/logs`.

- **Library:** tview on tcell (both permissive; k9s uses them). Its dialogs open over the screen
  they belong to (a widget tree with pages), where Bubble Tea, the other candidate, replaces the
  whole view on each screen change.
- **Layouts:** the profiles as a table above the logs, or a list with the selected profile's
  detail next to it (k9s style), switched with `v`; `tui.layout` / `--layout` sets the one to start
  with, otherwise the one used last (remembered in the state directory).
- **Screens:** the dashboard, a profile screen (what the profile asks for, with the changes made
  while running marked; what it carries; its traffic and connections), full-screen logs with filters
  by profile, level and text, and the key list.
- **Read only:** a run with `control: status` shows everything and greys the change keys out.
- **Size:** fitted to the terminal before every draw that follows a resize: the table's columns
  shrink, then the least needed go; an open dialog shrinks with the screen.
- **Updates:** only the UI goroutine touches the widgets and state; the poller, the log stream and
  the change requests hand their results to one pump goroutine, the only caller of tview's
  `QueueUpdate` (which waits for the event loop) and the one that stops the loop, so quitting never
  leaves a goroutine waiting. Log lines carry a sequence number, so a reconnected stream's repeats
  are dropped.
- **Tests:** tcell's simulation screen and a fake control socket: the screens are drawn and keys
  sent as a terminal would, and the changes made are checked.

**Inside subtun** (`--tui` on `up`, `k8s`, `docker`): the same TUI in subtun's own terminal.
- **Connection:** the same API and client, served in memory (`control.Server.InMemory`: HTTP over
  `net.Pipe` connections), so the TUI code is the same in both modes, and it works with `control:
  off`. Its server takes changes whatever `control` says (the person at subtun's terminal owns the
  run); the socket keeps following `control`. A one-profile run then keeps the root helper as a
  session, as with `control: full`, so routes can change.
- **The terminal:** subtun's own log output to the terminal is off while the TUI runs (the ring and
  the log file get everything; before and after, the terminal does). Standard error (fd 2) points
  at a pipe into the log meanwhile, so a kubeconfig login plugin or a library writing there doesn't
  scribble over the screen (a crash still reaches the terminal: `debug.SetCrashOutput`); login
  plugins get no stdin (`ExecProvider.StdinUnavailable`), since tcell reads the keyboard.
- **sudo:** sudo asks on the terminal (or through Touch ID), so starting the root helper lends the
  terminal (`privhelper.Lend`): the TUI suspends (tview `Suspend`, tcell leaves raw mode and the
  alternate screen) while sudo may ask, and comes back once the helper has connected. The suspend
  runs on the UI goroutine; the log stream keeps buffering meanwhile. A lend waits while the TUI is
  still starting, so sudo never asks while tcell takes the terminal over. `sudo -n -v` first: with
  a cached ticket (or no password needed) it doesn't step aside. Trade-offs: `verifypw` makes a
  sudoers rule for subtun alone fail the check (the TUI steps aside for nothing), and the failed
  check may be logged.
- **Stopping:** `q` and Ctrl-C ask; confirmed, the TUI cancels the engine's context, which the
  engine takes as a deliberate stop, like a signal. The TUI shows the stop and is closed by the
  engine after the capture and tunnels are down; the log lines from the stop (or the last 20, when
  the engine ended by itself, the TUI having shown the stop) are then printed to the terminal. A
  TUI that fails to start stops the run, which then exits with its error: nothing would show the
  run or stop it. The `--max-duration` watchdog gives the terminal back before it exits.

A daemon (subtun in the background, its log in the log file, attached to with `subtun tui`) is
deferred: started in the foreground for sudo, then detached.

## Targets

A profile's target is where its agent runs: a pod or a container that subtun creates and deletes
(the default), or an existing one it only starts its agent in. It stays per profile (`defaults:`
can't hold one), even when two profiles repeat it: the profile is what connects, whatever the
transport (Kubernetes, Docker, SSH).

```yaml
profiles:
  work:                          # subtun's own pod
    target: {k8s: {context: dev, namespace: ops, image: busybox:1.37, name: subtun-work,
                   resources: {requests: {cpu: 50m, memory: 64Mi}, limits: {memory: 512Mi}}}}
  shared:                        # an existing pod, by name or by labels
    target: {k8s: {context: dev, namespace: ops, create: false, selector: app=subtun-gw}}
  local:                         # subtun's own container, on a Compose network
    target: {docker: {network: dev_default, resources: {limits: {cpu: "1"}}}}
```

The same keys are flags of `subtun up --k8s` / `--docker` for a target given on the command line
(`--create`, `--name`, `-l/--selector`, `--image`, `--network`, `--requests`, `--limits`, `-n`, `-c`,
`--context`, `--kubeconfig`, `-H`), checked by the same validation (`config.Target.Validate`).

**Created** (`create`, the default):
- **Start:** pull the image if Docker doesn't have it, create the pod or container, wait until it
  runs (2 minutes for a pod; a reason that waiting won't fix ends it at once: the image pull
  backing off, an invalid image name, the container can't be created; a first failed pull, such as
  a registry's rate limit, is waited out), then connect as to any target: the agent is uploaded
  through exec and started.
- **Where:** the kube context and namespace (or the Docker host from a context) are fixed at the
  first connect (`transport.Picked`): switching kubectl's or docker's context while subtun runs
  moves neither the reconnects nor what subtun deletes.
- **Only its own:** subtun remembers the pod's UID (the container's ID) and deletes by it (a UID
  precondition), so a pod that took the name meanwhile is never touched; a create whose answer was
  lost (a stop meanwhile) is found again by a per-request label and deleted.
- **Reconnect:** the same pod again while it runs (the agent's cache too); gone or ended, a new
  one. A `profile reconnect` hands the pod to the next runner (`runner.keep`).
- **Stop:** deleted when the profile's tunnel ends for good: the profile stopped, given up, or
  subtun stopping (`tunnelSpec.release`, from the runner goroutine, after the routes are gone).
- **The pod:** a name from `name`, else `subtun-<profile>-<random>` (`generateName`, the profile
  made fit for a pod name: `_` and `.` become `-`, at most 40 characters); no service
  account token or service links; user and group 65534, non-root, all capabilities dropped, no
  privilege escalation, the default seccomp profile, a read-only root with an emptyDir on `/tmp`
  (`HOME=/tmp`, so the agent goes to `/tmp/.cache/subtun`): the restricted pod security level.
  Requests 10m CPU and 32Mi for what `resources` leaves unset, capped at its limits (with a limit
  alone, Kubernetes would request all of it); no limits by default (a namespace that requires them
  needs `resources`). `restartPolicy: Never`, a 1 s grace period.
- **The container:** the same user, no capabilities, `no-new-privileges`, a read-only root with a
  tmpfs `/tmp` mounted `exec` (Docker's default is `noexec`), `--rm`, on `network`; limits only
  (`resources.requests` is refused). The idle script is its entrypoint, so the image's own doesn't
  run (a pod's `command` does the same).
- **Labels:** `app.kubernetes.io/managed-by: subtun`, `subtun.dev/owner` (this user on this
  machine: a hash of the user and the machine's ID, the hardware UUID on macOS, `/etc/machine-id`
  on Linux, so it survives hostname changes), `subtun.dev/pid`; the profile as an annotation on a
  pod (a profile name isn't always a label value), a label on a container. A fixed `name` that
  exists and isn't this user's is refused, one another running subtun uses too; one of theirs left
  over is replaced. A reconnect reuses a pod only if this process created it (pid and UID).
- **Leftovers** (subtun killed, the laptop asleep): the main process is a shell loop that exits
  after 5 minutes without an agent process (`/proc/*/cmdline`, the bracketed pattern so grep
  doesn't find itself), so a pod left behind stops using anything; an image without `cat`, `tr`
  or `grep` can't tell, so its pod never exits by itself. The next start of a target in
  that namespace (or on that daemon) deletes this owner's pods that ended or whose subtun no longer
  runs on this machine (the pid label, `kill -0`). A Job with `ttlSecondsAfterFinished` would delete
  itself, but needs permissions on Jobs too: later, if leftovers bother anyone.
- **Permissions:** create, get, list and delete pods in the namespace, and exec.
- **Images:** the default is a pinned busybox (it needs a shell for the upload); a cluster that
  only takes images from its own registry needs its mirror in `image`.

**Existing** (`create: false`, or a `selector`, which only picks): by exact `name`, or by `selector`
(kubectl's label syntax; Docker: `key=value` pairs, all matching). A selector picks a running, ready
pod that isn't being deleted (a running, healthy container): the one used before while it still is
(its agent is cached there), else the newest; a reconnect whose pod went picks again. So pods that
come back under new names (a Deployment's) and several spares with the same labels both work.

**Why this shape** (decided while designing it): subtun manages what it needs instead of relying
on a pod kept for it, as sshuttle setups do with a script that runs a pod for the session; the
"existing" mode stays for clusters that allow exec but not creating pods. Following a Deployment by
name was dropped: its pods carry labels, which `selector` covers. `subtun k8s` and `subtun docker`
became `subtun up --k8s` / `--docker`: one entry point, with the target's keys as flags.

**Not done yet:** `subtun cleanup` for leftover pods (the next start covers it); an image with the
agent inside, so a created pod needs no upload, shell or writable directory (images published with
each release); spreading profiles that share a selector over its pods.

### SSH targets

`target: {ssh: {host, user, port, identity, jump}}`, or `subtun up --ssh [user@]host[:port] -i KEY
-J JUMP`: the agent runs on a host subtun logs in to, as the login user, the way sshuttle works.
Nothing to create: the transport only runs commands (`Execer`), and the shared bootstrap does the
rest (the probe now reports `uname -s`, so a host that isn't Linux gets the Python agent).

- **Client:** built in (`golang.org/x/crypto/ssh`), one connection per connect with a session per
  command (probe, upload, the agent), keepalives from `ServerAliveInterval` /
  `ServerAliveCountMax`, so a dead network closes the connection and reconnect takes over. The
  system `ssh` binary (everything OpenSSH supports, Kerberos and ControlMaster included) can be an
  option later; a connection per command, quoting through the remote shell and prompts in the
  middle of a run are its costs.
- **Configuration:** `ssh -G` resolves the host exactly as OpenSSH would (Include, Match, Host
  patterns, HostName, User, Port, IdentityFile, CertificateFile, ProxyJump, ProxyCommand, known_hosts
  files, StrictHostKeyChecking, HostKeyAlgorithms), with the target's own keys passed as ssh's flags
  so they win the same way. Without an ssh binary, OpenSSH's defaults. Writing a config parser was
  rejected: Match and Include are where they differ.
- **Logins:** keys only. The configured key files first (signed by the agent when it holds the same
  key, so no passphrase), then the agent's other keys (none with IdentitiesOnly): a server counts
  every key offered against MaxAuthTries. An encrypted key asks for its passphrase when the server
  accepts its public key (from `KEY.pub` or the file's header), once per run. Passwords and
  keyboard-interactive are left out: reconnects never prompt.
- **Host keys:** known_hosts as OpenSSH keeps it (plain, hashed, `@cert-authority`, `@revoked`). An
  unknown key is asked about on the terminal and saved (OpenSSH's `ask`; `yes` refuses, `accept-new`
  and `no` save without asking); with no terminal subtun refuses and names the `ssh` command that
  accepts it. A changed key is always refused. The server is asked for its keys in OpenSSH's order,
  narrowed to the types known_hosts has for the host; otherwise it may offer another type of its
  keys, which would look like a changed key.
- **Questions while running:** `transport.Ask` asks on `/dev/tty`, one question at a time; with
  `--tui` the terminal UI steps aside for it as it does for sudo (`transport.WithLend`).
- **Jump hosts and proxies:** ProxyJump hops are dialled through each other, each with its own
  `ssh -G` settings (`-i` is the destination's only, as in OpenSSH); ProxyCommand runs through
  `/bin/sh -c "exec ..."`. The routes keep out the address subtun's own connection goes to: the
  first hop, or the host; behind a ProxyCommand it isn't known.
- **sshuttle:** `subtun import sshuttle` turns `-r` into this target, with `-i`, `-J`, `-p` and `-l`
  from `--ssh-cmd`; a password in `-r` is left out.

## Decisions

- **Capture:** utun / TUN interface plus the gVisor network stack, with utun MTU 9000. Data never
  goes through pf; the firewall (pf, nftables, WFP) is only used for DNS capture, the kill switch and
  blocking IPv6, through a firewall driver.
- **OS-specific code behind drivers** (tun, routes, firewall, resolver), chosen by configuration.
- **Targets:** per profile; subtun creates its pod or container by default (and deletes it), or uses
  an existing one by name or labels; SSH hosts with a built-in client, keys only.
- **Remote side:** an agent over exec stdio (or an SSH session), not SSH `direct-tcpip`. Containers
  rarely run sshd, and UDP, remote DNS and host discovery need an agent anyway. The Go binary by
  default, the Python edition where the binary can't run (or the host isn't Linux).
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
  exclude that splits the routes inside the new LAN would put parts of it into the tunnel. The
  session helper can change routes while running (several profiles, `control: full`); what's
  missing is recomputing the automatic excludes when the networks change.
- **subtun's own connection moving inside the routes:** if the API server's, the Docker daemon's or
  the SSH server's address changes to one inside the routes after a reconnect, a one-shot helper (one
  profile, routes only, without `control: full`) can't change the routes: subtun only warns (restart
  to exclude it). With a session it is carved out. (Finding the pod again is solved: a pod picked by
  [labels](#targets), or created by subtun, is found again; one named exactly is looked for by name.)
- **Existing targets with neither a shell nor Python** (distroless static, scratch): an ephemeral
  debug container (Kubernetes) or a helper container in the target's network namespace (Docker).
  Pods and containers subtun creates run busybox, so they're fine.
- **Aborted streams:** smux has no reset. When the laptop side closes a stream abruptly, an agent
  still sending to it waits for window updates that never come, until the destination closes.
  Both agents behave the same; needs a reset signal in the protocol.
- **Remote clusters:** one has been measured so far: a single arm64 node on the same LAN, through its
  pod's own internet connection. A full tunnel reached about 20 MB/s down and 8-9 MB/s up, against
  53 and 38 MB/s directly (SOCKS through the same pod: 20 MB/s down). Where that limit sits (the
  node, its uplink, exec through the API server, smux) isn't known yet; transport flow control
  (several carriers in parallel against head-of-line blocking) waits for that answer. Through an SSH
  host on the same LAN, routes carried a download at 43.0 MB/s against 43.6 MB/s directly, so smux
  and the agent aren't the limit at that speed; exec through the API server is the next suspect.
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
- **ICMP through the tunnel** (ping, traceroute's probes, path MTU messages from beyond the target):
  not carried. An agent-side ping needs a raw or unprivileged ICMP socket in the target, which pods
  rarely allow.
- **UDP through the SOCKS proxy** (SOCKS5 UDP ASSOCIATE): not done; the capture carries UDP.
- **Docker transport upload** is ~25 % below Kubernetes on the same Mac (147 vs 193 MB/s through
  utun). Candidate: one write per smux frame straight onto the hijacked Docker connection, where
  the Kubernetes path batches through client-go.
- **The system `ssh` as an SSH client:** for what the built-in client doesn't do (Kerberos/GSSAPI,
  ControlMaster, rare options). Not needed so far; certificates, IdentitiesOnly and ProxyCommand are
  unit-tested but haven't met real servers yet.
