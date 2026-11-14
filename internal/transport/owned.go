package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"
)

// The labels on the pods and containers subtun creates: who made them, so
// leftovers can be told from another running subtun's.
const (
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelProfile   = "subtun.dev/profile"
	LabelOwner     = "subtun.dev/owner" // this user on this machine, hashed
	LabelPID       = "subtun.dev/pid"
	ManagedBy      = "subtun"
)

// IdleExit is how long a pod or container subtun created runs without an
// agent before it exits by itself (a killed subtun left it behind).
const IdleExit = 5 * time.Minute

// IdleScript is the main process of a pod or container subtun creates: it
// exits once no agent has run in it for IdleExit. The bracket keeps grep
// from finding itself.
// An image without cat, tr or grep can't tell: it never exits then (a
// leftover is still deleted by the next start).
var IdleScript = `for c in cat tr grep; do command -v "$c" >/dev/null 2>&1 || { while :; do sleep 3600; done; }; done
i=0; while sleep 30; do
if cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\0' ' ' | grep -q '[s]ubtun-agent'; then i=0; else i=$((i+30)); fi
[ "$i" -ge ` + strconv.Itoa(int(IdleExit.Seconds())) + ` ] && exit 0
done`

// Owner is this user on this machine, hashed: a label value. The machine
// is its ID (the hardware UUID on macOS, /etc/machine-id on Linux), which
// stays when the hostname changes with the network and differs between
// machines of the same name; else the hostname.
var Owner = sync.OnceValue(func() string {
	who := strconv.Itoa(os.Getuid())
	if u, err := user.Current(); err == nil {
		who = u.Username
	}
	machine := machineID()
	if machine == "" {
		machine, _ = os.Hostname()
	}
	sum := sha256.Sum256([]byte(who + "@" + machine))
	return hex.EncodeToString(sum[:])[:16]
})

// OwnLabels are the labels of a pod or container this process creates.
func OwnLabels() map[string]string {
	return map[string]string{LabelManagedBy: ManagedBy, LabelOwner: Owner(), LabelPID: strconv.Itoa(os.Getpid())}
}

// Ours reports whether labels are those of something this user's subtun
// created on this machine.
func Ours(labels map[string]string) bool {
	return labels[LabelManagedBy] == ManagedBy && labels[LabelOwner] == Owner()
}

// Alive reports whether the subtun of that process id (a label value)
// still runs on this machine.
func Alive(pid string) bool {
	n, err := strconv.Atoi(pid)
	if err != nil || n <= 0 {
		return false
	}
	return n == os.Getpid() || processAlive(n)
}
