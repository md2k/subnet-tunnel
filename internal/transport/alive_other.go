//go:build !unix

package transport

// processAlive can't tell here: a process is taken to be running, so only
// pods and containers that have ended count as leftovers.
func processAlive(int) bool { return true }
