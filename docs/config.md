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
`--agent-dir`, `--tun-addr`, `--mtu`). CIDRs and `-x/--exclude` given on the command line are
**added** to the profile's. Without a config file, the same flags work on `subtun k8s` and
`subtun docker`.

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
connection to the API server or Docker daemon is excluded automatically. IPv6 and DNS are not
redirected yet, so they still leave directly in this mode.

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
