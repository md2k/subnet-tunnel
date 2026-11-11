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
  apart. CIDRs that contain the API server or Docker daemon address are refused (routing loop).

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
- **Lifecycle.** Closing subtun sends EOF on the agent's stdin and the agent exits. If the carrier
  drops (pod deleted, network lost), subtun notices within seconds and exits with an error.

## Privileges

subtun runs as the user. Creating a utun interface, adding routes and (later) writing resolver
entries need root; packet handling never does. Root work is done by a small helper, `subtun helper`,
that subtun starts through `sudo` (sudo asks for the password on the terminal).

### How the helper is trusted

- subtun creates a unix socket in a private directory (`~/Library/Caches/subtun/run`, mode 0700,
  socket 0600) and starts `/usr/bin/sudo -- <subtun> helper --socket <path>`, passing a random
  token on the helper's stdin.
- The helper refuses to run unless it is root and started through sudo (`SUDO_UID`). It only
  connects to a socket whose directory and file belong to that user and aren't accessible to
  anyone else, then proves itself with the token.
- It accepts three commands, in lock-step: `create_tun` (MTU and address validated), `add_route`
  (IPv4, host bits zero, never the default route, loopback or multicast) and `done`. It runs
  `/sbin/ifconfig` and `/sbin/route` with fixed argument lists, never a shell. The utun's file
  descriptor goes back over the socket (SCM_RIGHTS).

### Modes

| | One-shot (default, implemented) | Session (planned, opt-in) |
|---|---|---|
| sudo prompts | one, at start | one, at start |
| Root process after setup | none: the helper exits | the helper stays up for the session |
| Changing CIDRs / DNS | restart subtun | at runtime, through subtun's local control API |
| Cleanup | automatic: routes live on the utun, and macOS removes the utun and its routes when subtun exits, crashes or is killed | the helper undoes its changes when subtun disconnects, including resolver entries |
| Split DNS (`/etc/resolver`) | entries written at start; removing them needs root again (planned: cleanup on next start, or a sudo at exit) | written and removed by the helper |
| Risk | smallest: root exists only for the seconds of setup | a root process stays reachable (only by subtun, over the private socket) for the whole session |

Both modes use the same helper and command loop; session mode just doesn't end it after setup. If
subtun goes away before `done`, the helper removes the routes it added and closes the utun.

How to use: one-shot is what happens when you pass CIDRs. Session mode will be a flag once the
control API exists.

## Decisions

- **Capture:** utun / TUN interface plus the gVisor network stack, with utun MTU 9000. Never pf.
- **Remote side:** an agent over exec stdio, not SSH `direct-tcpip`. Containers rarely run sshd,
  and UDP, remote DNS and host discovery need an agent anyway. The Go binary by default, the
  Python edition where the binary can't run.
- **Agent location:** never a shared, world-writable path. Per-user 0700 directories, `$HOME` first.
- **DNS:** macOS supplemental resolvers (`/etc/resolver/<domain>`, or one dynamic entry with a list
  of match domains) send only the selected domains to the tool. Optional regex matching applies
  inside the tool, to the queries that reach it.
- **Privileges:** the tool runs as the user; root only in the helper, one-shot by default, session
  mode opt-in (see Privileges).
- **Pure Go:** `CGO_ENABLED=0`, a single static binary per OS and architecture.

## Open questions

- **Targets with neither a shell nor Python** (distroless static, scratch): an ephemeral debug
  container (Kubernetes) or a helper container in the target's network namespace (Docker).
- **Aborted streams:** smux has no reset. When the laptop side closes a stream abruptly, an agent
  still sending to it waits for window updates that never come, until the destination closes.
  Both agents behave the same; needs a reset signal in the protocol.
- **Transport flow control on remote clusters:** several carriers in parallel to avoid head-of-line
  blocking, once measured against a real remote cluster.
- **Coexistence** with other VPN or security software that owns its own utun interface or pf anchor.
- **Excluding addresses inside captured CIDRs** (sshuttle's `-x`): today a CIDR containing the API
  server is refused instead.
