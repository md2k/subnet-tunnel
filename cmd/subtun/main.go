// Command subtun routes chosen subnets and DNS domains from this machine
// through a remote host, Kubernetes pod or container.
package main

import (
	"os"

	"github.com/md2k/subnet-tunnel/internal/cli"
)

func main() { os.Exit(cli.Execute()) }
