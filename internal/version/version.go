// Package version holds build metadata, set at link time with -ldflags -X
// (see the Makefile and scripts/release.sh).
package version

var (
	// Version is the release tag, or `git describe` output for local builds.
	Version = "dev"
	// GitSHA is the short commit the binary was built from.
	GitSHA = "none"
	// BuildDate is the UTC build time, RFC 3339.
	BuildDate = "unknown"
)

// String returns "version (sha, date)".
func String() string { return Version + " (" + GitSHA + ", " + BuildDate + ")" }
