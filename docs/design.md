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

## Architecture

```
app ──► SOCKS5 (later: utun + gVisor) ──► tunnel client ══ carrier ══► agent ──► destination
         on the laptop                     smux streams    exec stdio   in the target
```

- **Agent.** A small static Linux binary (`cmd/subtun-agent`, ~3.5 MB), embedded in subtun for
  amd64 and arm64. subtun probes the target's architecture, uploads the matching agent over exec
  (`sh` + `cat`, into `/tmp` or `--agent-dir`) and caches it under its checksum, so later
  connections skip the upload.
- **Carrier.** The agent's stdin/stdout over the exec API: Kubernetes through client-go (WebSocket,
  SPDY fallback) with the user's kubeconfig; Docker through the Engine API with the user's docker
  context. No kubectl, port-forward or sshd involved.
- **Protocol.** The agent first writes a hello line (`subtun-agent <proto> <version> <sha256>`);
  subtun checks the protocol version and that the checksum matches the binary it uploaded. Then
  smux v2 runs over the carrier, one stream per connection: a request (`connect host:port`), a
  status reply, then raw bytes. Hostnames resolve on the agent side. Half-close passes through.
- **Flow control.** smux per-stream window 4 MB, session buffer 32 MB, so one stream is not capped
  at window/RTT on remote clusters.
- **Lifecycle.** Closing subtun sends EOF on the agent's stdin and the agent exits. If the carrier
  drops (pod deleted, network lost), subtun notices within seconds and exits with an error.

## Decisions

- **Capture:** utun / TUN interface plus the gVisor network stack, with utun MTU 9000. Never pf.
- **Remote side:** the Go agent over exec stdio, not SSH `direct-tcpip`. Containers rarely run sshd,
  and UDP, remote DNS and host discovery need an agent anyway.
- **DNS:** macOS supplemental resolvers (`/etc/resolver/<domain>`, or one dynamic entry with a list
  of match domains) send only the selected domains to the tool. Optional regex matching applies
  inside the tool, to the queries that reach it.
- **Privileges:** the tool runs as the user. It asks for sudo only for the steps that need root:
  creating the interface, changing routes, writing resolver entries.
- **Pure Go:** `CGO_ENABLED=0`, a single static binary per OS and architecture.

## Open questions

- **Agent delivery without a shell** (distroless images): ephemeral debug container, or a sidecar.
- **Transport flow control on remote clusters:** several carriers in parallel to avoid head-of-line
  blocking, once measured against a real remote cluster.
- **Coexistence** with other VPN or security software that owns its own utun interface or pf anchor.
- **Root step on macOS:** pass the utun file descriptor from a short-lived root helper to the user
  process, or keep a small root helper for the session's lifetime.
