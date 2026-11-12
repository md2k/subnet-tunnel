# Configuration

Everything can be given on the command line, or kept in named profiles in a YAML file and started
with `subtun up NAME`.

## File

Location: `--config FILE`, else `$SUBTUN_CONFIG`, else `$XDG_CONFIG_HOME/subtun/config.yaml`, else
`~/.config/subtun/config.yaml`. Parsing is strict: an unknown key is an error, so a typo can't
silently drop a setting.

```yaml
profiles:
  dev-cluster:                     # lowercase letters, digits, '.', '_', '-'
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

  local-app:
    target:
      docker:
        host: unix:///var/run/docker.sock   # default: $DOCKER_HOST, then the docker context
        context: desktop-linux               # default: $DOCKER_CONTEXT, then the current context
        container: app                       # required
    socks: 127.0.0.1:1081
```

A profile needs `routes`, `socks` or both.

## Command line and profiles together

```sh
subtun up                                  # list profiles
subtun up dev-cluster                      # run it
subtun up dev-cluster --dry-run            # show the planned routes and exit
subtun up dev-cluster 10.50.0.0/16 -x 10.50.1.0/24 --socks 127.0.0.1:1082
```

Flags given on the command line override the profile's values (`--socks`, `--agent`,
`--agent-dir`, `--tun-addr`, `--mtu`, `--dns-capture`, `--dns-servers`, `--dns-fallback`). CIDRs,
`-x/--exclude`, `--dns-domain` and `--dns-pattern` given on the command line are **added** to the
profile's. Without a config file, the same flags work on `subtun k8s` and `subtun docker`.

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
machine is back to normal. Your LAN stays local (its own route is more specific), and subtun's own
connection to the API server or Docker daemon is excluded automatically. Add `--dns-domain .` (or
`dns.domains: ["."]`) to resolve every name through the tunnel as well. IPv6 is not redirected yet,
so it still leaves directly in this mode.

## Safety checks

Before connecting or asking for sudo, subtun refuses a route that would capture your default
gateway: one at least as specific as the local network holding it (`192.168.1.0/24` when that is
your LAN). Broader routes such as `10.0.0.0/8` or a full tunnel are fine, because the LAN's own route
is more specific and keeps the gateway reachable.

It warns when a route overlaps a network of one of this machine's interfaces (your LAN, a VPN
client's interface). The more specific route wins, and the warning says which side that is.

Excluded automatically, and listed by `--dry-run`: subtun's own utun address, and, when the tunnel
is up, the address subtun itself connects to (the Kubernetes API server, a remote Docker daemon).

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
| `domains` | `--dns-domain` (repeatable, comma-separated) | none | suffixes resolved through the tunnel; `.` = every name |
| `patterns` | `--dns-pattern` (repeatable) | none | regular expressions resolved through the tunnel |
| `servers` | `--dns-servers` | `auto` | DNS servers whose queries are captured: `auto` (the system's) or IPv4 addresses |
| `fallback` | `--dns-fallback` | `system` | resolver for everything else: `system` (the servers the query was meant for) or `IP[:port]` |
| `capture` | `--dns-capture` | `firewall` | `firewall` (pf on macOS) or `off` |

DNS capture is on as soon as `domains` or `patterns` are set, and it needs routes: it runs with the
utun capture, and the addresses it returns are reached through your routes.

**Matching.** A domain matches itself and every name below it: `company.com` matches
`company.com` and `db.eu.company.com`, not `badcompany.com`. A leading `*.`, `.` or `.*.` (sshuttle's
pattern form) is ignored, so `.*.company.com` from an sshuttle file works as is. Patterns are Go
regular expressions, matched against the lowercase name without the trailing dot. They aren't
anchored, so write `^` and `$` where you need them (sshuttle used Python's `re.match`, which anchors
at the start only).

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
when the fallback is one of the captured servers.

**Limits.**
- One DNS-capturing subtun at a time: a second one refuses to start, since it would take over the
  first one's rules.
- If the fallback resolver is inside one of your routes, unmatched names fail: their UDP queries go
  into the utun, which carries TCP only so far. `--dry-run` warns; exclude the resolver's address or
  match every name with `.`.
- If the helper itself is killed (`kill -9`), the rules stay and DNS for the captured servers stops
  working once subtun exits; subtun says so. Remove them with
  `sudo pfctl -a com.apple/subtun -F nat && sudo pfctl -a com.apple/subtun -F rules`.
- macOS only for now; `override` and `supplemental` capture modes (via the system resolver
  configuration instead of the firewall) are planned.
