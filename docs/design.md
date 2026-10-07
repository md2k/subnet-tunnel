# Design

Status: design stage. This document records the measurements that drove the design and the
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

## Decisions

- **Capture:** utun / TUN interface plus the gVisor network stack, with utun MTU 9000. Never pf.
- **DNS:** macOS supplemental resolvers (`/etc/resolver/<domain>`, or one dynamic entry with a list
  of match domains) send only the selected domains to the tool. Optional regex matching applies
  inside the tool, to the queries that reach it.
- **Privileges:** the tool runs as the user. It asks for sudo only for the steps that need root:
  creating the interface, changing routes, writing resolver entries.
- **Pure Go:** `CGO_ENABLED=0`, a single static binary per OS and architecture.

## Open questions

- **Remote side:** SSH `direct-tcpip` channels (only sshd needed, TCP only), or a small static Go
  agent copied over the transport (needed for UDP, remote DNS, host discovery)?
- **Transport flow control:** per-stream window of at least bandwidth × round-trip time. Multiple
  streams or connections to avoid head-of-line blocking on remote clusters.
- **Coexistence** with other VPN or security software that owns its own utun interface or pf anchor.
- **Root step on macOS:** pass the utun file descriptor from a short-lived root helper to the user
  process, or keep a small root helper for the session's lifetime.
