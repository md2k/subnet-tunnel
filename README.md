# subnet-tunnel (`subtun`)

Route chosen subnets and DNS domains from your laptop through a remote host or a Kubernetes pod,
as if you were on that network. A single static Go binary: no Python, no runtime dependencies.

Inspired by [sshuttle](https://github.com/sshuttle/sshuttle). Built because on macOS sshuttle's
pf-based capture caps upload at a few MB/s, while a utun interface with a userspace TCP/IP stack
reached ~170 MB/s end to end in the same test (see [docs/design.md](docs/design.md)).

> **Status:** design stage. Nothing to install yet.

## Planned

- Capture through a TUN interface (utun on macOS, TUN on Linux, wintun on Windows) with the
  [gVisor](https://gvisor.dev) userspace network stack. No pf or iptables redirects.
- Split routing: only the CIDRs you list go through the tunnel.
- Split DNS: only the domains you list resolve through the tunnel; everything else uses your normal DNS.
- Transports: SSH to any host, and `kubectl port-forward` / `exec` into a pod.
- Runs as your user. sudo is requested only for the steps that need root (interface, routes, resolver entries).

## Documentation

- [Design](docs/design.md): measurements, architecture and open questions.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).
