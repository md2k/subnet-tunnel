# subtun agent, Python edition.
#
# subtun sends this source over the exec session's stdin and runs it with
# `python3 -c <loader>`, the way sshuttle starts its server: nothing is
# written to the target. It speaks the same protocol as cmd/subtun-agent
# (internal/proto): a hello line on stdout, then smux v2 on stdin/stdout with
# one stream per connection carrying a request, a status reply and raw bytes.
#
# Python 3.6+, standard library only.

import errno
import hashlib
import os
import platform
import socket
import struct
import sys
import threading
import time

VERSION = "__SUBTUN_VERSION__"
PROTO = 1

# smux v2 framing (github.com/xtaci/smux): little-endian header
# ver(1) cmd(1) length(2) stream-id(4), payload follows.
SMUX_VERSION = 2
CMD_SYN, CMD_FIN, CMD_PSH, CMD_NOP, CMD_UPD = 0, 1, 2, 3, 4
HEADER = struct.Struct("<BBHI")
UPDATE = struct.Struct("<II")  # consumed, window
INITIAL_PEER_WINDOW = 262144  # smux initialPeerWindow, until the peer's first UPD
WINDOW = 4 << 20  # our per-stream receive window (= MaxStreamBuffer in proto.MuxConfig)
MAX_FRAME = 65535
KEEPALIVE = 10  # seconds; the client drops the session after 30 s of silence

# Stream request/response (big-endian, see internal/proto).
CMD_CONNECT = 1
ST_OK, ST_FAILURE, ST_REFUSED, ST_UNREACHABLE, ST_TIMEOUT, ST_DNS, ST_BAD_REQUEST = range(7)
MAX_ADDR = 512
MAX_MSG = 512
REQUEST_TIMEOUT = 30
DIAL_TIMEOUT = 10

VERBOSE = "-v" in sys.argv[1:]
_log_lock = threading.Lock()


def _q(v):
    s = str(v)
    if s and not any(c in s for c in ' ="\\\n'):
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def log(level, msg, **kv):
    """slog-style text lines on stderr; subtun relays them into its log."""
    if level == "DEBUG" and not VERBOSE:
        return
    parts = ["level=" + level, "msg=" + _q(msg)]
    parts += ["%s=%s" % (k, _q(v)) for k, v in sorted(kv.items())]
    with _log_lock:
        sys.stderr.write(" ".join(parts) + "\n")
        sys.stderr.flush()


class Session(object):
    """smux v2 server side over the carrier (the agent's stdin/stdout)."""

    def __init__(self, inp, out):
        self.inp = inp
        self.out = out
        self.wlock = threading.Lock()
        self.slock = threading.Lock()
        self.streams = {}
        self.closed = False

    def send(self, cmd, sid, data=b""):
        frame = HEADER.pack(SMUX_VERSION, cmd, len(data), sid) + data
        with self.wlock:
            if self.closed:
                raise IOError("session closed")
            self.out.write(frame)
            self.out.flush()

    def forget(self, sid):
        with self.slock:
            self.streams.pop(sid, None)

    def run(self):
        read = self.inp.read
        try:
            while True:
                hdr = read(HEADER.size)
                if len(hdr) < HEADER.size:
                    return  # carrier closed: the normal end of a session
                ver, cmd, length, sid = HEADER.unpack(hdr)
                if ver != SMUX_VERSION:
                    log("ERROR", "bad smux version", got=ver)
                    return
                data = read(length) if length else b""
                if len(data) < length:
                    return
                if cmd == CMD_PSH:
                    with self.slock:
                        st = self.streams.get(sid)
                    if st is not None:
                        st.push(data)
                elif cmd == CMD_SYN:
                    self.accept(sid)
                elif cmd == CMD_FIN:
                    with self.slock:
                        st = self.streams.get(sid)
                    if st is not None:
                        st.remote_fin()
                elif cmd == CMD_UPD:
                    if length != UPDATE.size:
                        log("ERROR", "bad window update", length=length)
                        return
                    with self.slock:
                        st = self.streams.get(sid)
                    if st is not None:
                        st.update(*UPDATE.unpack(data))
                elif cmd != CMD_NOP:
                    log("ERROR", "unknown smux command", cmd=cmd)
                    return
        finally:
            self.shutdown()

    def accept(self, sid):
        with self.slock:
            if sid in self.streams:
                return
            st = Stream(self, sid)
            self.streams[sid] = st
        t = threading.Thread(target=handle, args=(st,))
        t.daemon = True
        t.start()

    def shutdown(self):
        with self.wlock:
            self.closed = True
        with self.slock:
            streams = list(self.streams.values())
            self.streams.clear()
        for st in streams:
            st.kill()

    def keepalive(self):
        while True:
            time.sleep(KEEPALIVE)
            try:
                self.send(CMD_NOP, 0)
            except Exception:
                return


class Stream(object):
    """One smux stream with v2 flow control, mirroring xtaci/smux."""

    def __init__(self, sess, sid):
        self.sess = sess
        self.sid = sid
        self.rcond = threading.Condition()
        self.buf = bytearray()
        self.fin = False  # peer closed its write side
        self.dead = False  # session gone or stream aborted
        self.num_read = 0  # bytes consumed, mod 2**32
        self.incr = 0
        self.wcond = threading.Condition()
        self.num_written = 0  # bytes sent, mod 2**32
        self.peer_consumed = 0
        self.peer_window = INITIAL_PEER_WINDOW
        self.write_closed = False

    # -- receive side
    def push(self, data):
        with self.rcond:
            self.buf += data
            self.rcond.notify()

    def remote_fin(self):
        with self.rcond:
            self.fin = True
            self.rcond.notify_all()

    def read(self, n, timeout=None):
        """Up to n bytes; b"" at EOF. socket.timeout if nothing arrives in time."""
        deadline = None if timeout is None else time.time() + timeout
        with self.rcond:
            while not self.buf and not self.fin and not self.dead:
                left = None if deadline is None else deadline - time.time()
                if left is not None and left <= 0:
                    raise socket.timeout("stream read timed out")
                self.rcond.wait(left)
            if not self.buf:
                return b""
            data = bytes(self.buf[:n])
            del self.buf[:n]
            self.num_read = (self.num_read + len(data)) & 0xFFFFFFFF
            self.incr += len(data)
            notify = 0
            if self.incr >= WINDOW // 2 or self.num_read == len(data):
                notify = self.num_read
                self.incr = 0
        if notify:
            self.sess.send(CMD_UPD, self.sid, UPDATE.pack(notify, WINDOW))
        return data

    def read_exact(self, n, timeout):
        out = b""
        deadline = time.time() + timeout
        while len(out) < n:
            chunk = self.read(n - len(out), max(0.0, deadline - time.time()))
            if not chunk:
                raise EOFError("stream closed")
            out += chunk
        return out

    # -- send side
    def update(self, consumed, window):
        with self.wcond:
            self.peer_consumed = consumed
            self.peer_window = window
            self.wcond.notify_all()

    def write(self, data):
        view = memoryview(data)
        while len(view):
            with self.wcond:
                while True:
                    if self.dead or self.write_closed:
                        raise IOError("stream closed")
                    inflight = (self.num_written - self.peer_consumed) & 0xFFFFFFFF
                    if inflight > 0x7FFFFFFF:
                        raise IOError("peer acknowledged more than was sent")
                    window = self.peer_window - inflight
                    if window > 0:
                        break
                    self.wcond.wait()
                n = min(len(view), window, MAX_FRAME)
                self.num_written = (self.num_written + n) & 0xFFFFFFFF
            self.sess.send(CMD_PSH, self.sid, view[:n].tobytes())
            view = view[n:]

    def close_write(self):
        """Half-close: the peer reads EOF, we can still receive."""
        with self.wcond:
            if self.write_closed or self.dead:
                return
            self.write_closed = True
            self.wcond.notify_all()
        try:
            self.sess.send(CMD_FIN, self.sid)
        except Exception:
            pass

    def kill(self):
        with self.rcond:
            self.dead = True
            self.rcond.notify_all()
        with self.wcond:
            self.dead = True
            self.wcond.notify_all()


def reply(st, status, msg=""):
    body = msg.encode("utf-8", "replace")[:MAX_MSG]
    st.write(struct.pack(">BH", status, len(body)) + body)


def split_host_port(addr):
    host, sep, port = addr.rpartition(":")
    if not sep or not host or not port.isdigit():
        raise ValueError("bad address %r" % addr)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host, int(port)


def dial(host, port):
    sock = socket.create_connection((host, port), timeout=DIAL_TIMEOUT)
    sock.settimeout(None)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def status_for(err):
    if isinstance(err, socket.gaierror):
        return ST_DNS
    if isinstance(err, ConnectionRefusedError):
        return ST_REFUSED
    if isinstance(err, socket.timeout):
        return ST_TIMEOUT
    if isinstance(err, OSError) and err.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        return ST_UNREACHABLE
    return ST_FAILURE


def handle(st):
    try:
        try:
            ver, cmd, alen = struct.unpack(">BBH", st.read_exact(4, REQUEST_TIMEOUT))
            if ver != PROTO or alen == 0 or alen > MAX_ADDR:
                log("WARN", "bad request", stream=st.sid, version=ver, addr_len=alen)
                return
            addr = st.read_exact(alen, REQUEST_TIMEOUT).decode("utf-8", "replace")
        except (EOFError, socket.timeout, IOError) as e:
            log("WARN", "bad request", stream=st.sid, err=e)
            return
        if cmd != CMD_CONNECT:
            reply(st, ST_BAD_REQUEST, "unsupported command")
            return
        try:
            host, port = split_host_port(addr)
            sock = dial(host, port)
        except Exception as e:
            log("DEBUG", "dial failed", stream=st.sid, addr=addr, err=e)
            reply(st, status_for(e), "dial %s: %s" % (addr, e))
            return
        try:
            reply(st, ST_OK)
            log("DEBUG", "connected", stream=st.sid, addr=addr)
            relay(st, sock)
        finally:
            sock.close()
    except Exception as e:
        log("DEBUG", "stream ended", stream=st.sid, err=e)
    finally:
        st.close_write()
        st.sess.forget(st.sid)


def relay(st, sock):
    counts = {"up": 0, "down": 0}
    start = time.time()

    def abort():
        st.kill()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def sock_to_stream():
        try:
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                st.write(data)
                counts["down"] += len(data)
            st.close_write()
        except Exception:
            abort()

    t = threading.Thread(target=sock_to_stream)
    t.daemon = True
    t.start()
    try:
        while True:
            data = st.read(65536)
            if not data:
                break
            sock.sendall(data)
            counts["up"] += len(data)
        if not st.dead:
            sock.shutdown(socket.SHUT_WR)
    except Exception:
        abort()
    t.join()
    log("DEBUG", "closed", stream=st.sid, up=counts["up"], down=counts["down"],
        dur="%.3fs" % (time.time() - start))


def main():
    src = globals().get("_src") or b""
    digest = hashlib.sha256(src).hexdigest() if src else "-"
    version = "%s+py%d.%d" % (VERSION, sys.version_info[0], sys.version_info[1])
    out = sys.stdout.buffer
    out.write(("subtun-agent %d %s %s\n" % (PROTO, version, digest)).encode("ascii"))
    out.flush()

    sess = Session(sys.stdin.buffer, out)
    ka = threading.Thread(target=sess.keepalive)
    ka.daemon = True
    ka.start()
    log("INFO", "agent ready", proto=PROTO, version=version, python=platform.python_version())
    sess.run()
    log("INFO", "session closed")
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
