#!/bin/sh
# The jump host of the dev setup (test/dev/compose.yaml): allow TCP
# forwarding, which ProxyJump needs.
sed -i "s/^AllowTcpForwarding no/AllowTcpForwarding yes/" /config/sshd/sshd_config
