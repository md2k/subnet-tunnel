//go:build !windows

package privhelper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// writeMsg sends one JSON line, with optional file descriptors attached.
func writeMsg(c *net.UnixConn, v any, fds ...int) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	var oob []byte
	if len(fds) > 0 {
		oob = syscall.UnixRights(fds...)
	}
	_ = c.SetWriteDeadline(time.Now().Add(ioTimeout))
	n, oobn, err := c.WriteMsgUnix(b, oob, nil)
	if err != nil {
		return err
	}
	if n != len(b) || oobn != len(oob) {
		return fmt.Errorf("short write (%d/%d bytes, %d/%d oob)", n, len(b), oobn, len(oob))
	}
	return nil
}

// readMsg reads one JSON line and any file descriptors that came with it.
// The protocol is strictly request/response, so a line never shares a read
// with the next one. A zero deadline waits indefinitely.
func readMsg(c *net.UnixConn, v any, deadline time.Time) ([]*os.File, error) {
	_ = c.SetReadDeadline(deadline)
	var line []byte
	var files []*os.File
	buf := make([]byte, maxLine)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	for {
		n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
		if oobn > 0 {
			fs, perr := parseRights(oob[:oobn])
			files = append(files, fs...)
			if perr != nil {
				closeAll(files)
				return nil, perr
			}
		}
		line = append(line, buf[:n]...)
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			if i != len(line)-1 {
				closeAll(files)
				return nil, errors.New("unexpected data after message")
			}
			if err := json.Unmarshal(line[:i], v); err != nil {
				closeAll(files)
				return nil, fmt.Errorf("bad message: %w", err)
			}
			return files, nil
		}
		if err != nil {
			closeAll(files)
			return nil, err
		}
		if len(line) > maxLine {
			closeAll(files)
			return nil, errors.New("message too long")
		}
	}
}

func parseRights(oob []byte) ([]*os.File, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var files []*os.File
	for _, m := range msgs {
		fds, err := syscall.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			// Non-blocking before wrapping, so the File uses Go's poller and
			// Close interrupts a pending Read.
			_ = syscall.SetNonblock(fd, true)
			files = append(files, os.NewFile(uintptr(fd), "passed-fd"))
		}
	}
	return files, nil
}

func closeAll(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}
