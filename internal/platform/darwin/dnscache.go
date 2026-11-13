//go:build darwin

package darwin

// DNSCache flushes macOS's DNS cache: the directory service cache, then
// mDNSResponder's (SIGHUP), the way Apple documents it.
type DNSCache struct{}

// Flush implements platform.DNSCache.
func (DNSCache) Flush() error {
	if err := run("/usr/bin/dscacheutil", "-flushcache"); err != nil {
		return err
	}
	return run("/usr/bin/killall", "-HUP", "mDNSResponder")
}
