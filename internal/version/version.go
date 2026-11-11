// Package version holds build metadata, set at link time with -ldflags -X.
package version

var (
	// Version is the release version, or "dev" for local builds.
	Version = "dev"
	// Commit is the short git commit the binary was built from.
	Commit = "none"
)

// String returns "version (commit)".
func String() string { return Version + " (" + Commit + ")" }
