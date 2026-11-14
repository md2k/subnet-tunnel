package transport

import (
	"context"
	"os/exec"
	"regexp"
	"time"
)

var platformUUID = regexp.MustCompile(`"IOPlatformUUID" = "([0-9A-Fa-f-]+)"`)

// machineID is the Mac's hardware UUID; "": unknown.
func machineID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	if m := platformUUID.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}
