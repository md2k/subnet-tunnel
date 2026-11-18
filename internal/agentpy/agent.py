# subtun agent, Python edition.
#
# subtun sends this source over the exec session's stdin and runs it with
# `python3 -c <loader>`, the way sshuttle starts its server: nothing is
# written to the target. It speaks the same protocol as cmd/subtun-agent
# (internal/proto): a hello line on stdout, then smux v2 on stdin/stdout with
# one stream per connection carrying a request, a status reply and raw bytes,
# or one DNS query and its answer.
#
# Python 3.6+, standard library only.

import collections
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
CMD_CONNECT, CMD_DNS, CMD_UDP = 1, 2, 3
MAX_DATAGRAM = 65535
UDP_SOCKET_BUFFER = 4 << 20  # asked for a flow's socket (Linux gives at most rmem_max, doubled)
UDP_QUEUE_BYTES = 4 << 20  # read from a flow's socket, not in the stream yet
DATAGRAM_OVERHEAD = 64  # what a queued datagram costs on top of its bytes
UDP_ERROR_STREAK = 1000  # read errors in a row, with no datagram between, end a flow
ST_OK, ST_FAILURE, ST_REFUSED, ST_UNREACHABLE, ST_TIMEOUT, ST_DNS, ST_BAD_REQUEST = range(7)
MAX_ADDR = 512
MAX_MSG = 512
REQUEST_TIMEOUT = 30
DIAL_TIMEOUT = 10

# DNS queries (CMD_DNS) go unchanged to the target's own resolver.
RESOLVER_SYSTEM = "-"
RESOLV_CONF = "/etc/resolv.conf"
MIN_DNS = 12  # header
DNS_UDP_TIMEOUT = 2
DNS_TCP_TIMEOUT = 5
DNS_TOTAL_TIMEOUT = 10
MAX_NAMESERVERS = 3

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
        """n bytes; EOFError at EOF; timeout None waits as long as it takes."""
        out = b""
        deadline = None if timeout is None else time.time() + timeout
        while len(out) < n:
            chunk = self.read(n - len(out), None if deadline is None else max(0.0, deadline - time.time()))
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
        """Half-close: the peer reads EOF, we can still receive. After a kill
        too, so the peer hears that the stream ended."""
        with self.wcond:
            if self.write_closed:
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
        if cmd == CMD_DNS:
            handle_dns(st, addr)
            return
        if cmd == CMD_UDP:
            handle_udp(st, addr)
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


def handle_dns(st, addr):
    if addr != RESOLVER_SYSTEM:
        reply(st, ST_BAD_REQUEST, "unsupported resolver " + addr)
        return
    n, = struct.unpack(">H", st.read_exact(2, REQUEST_TIMEOUT))
    if n < MIN_DNS:
        log("WARN", "bad DNS query", stream=st.sid, length=n)
        return
    query = st.read_exact(n, REQUEST_TIMEOUT)
    try:
        answer = exchange_any(query)
    except Exception as e:
        log("DEBUG", "DNS query failed", stream=st.sid, err=e)
        reply(st, status_for(e), "DNS: %s" % e)
        return
    reply(st, ST_OK)
    st.write(struct.pack(">H", len(answer)) + answer)


def udp_dial(host, port):
    family, kind, proto, _, sockaddr = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)[0]
    sock = socket.socket(family, kind, proto)
    sock.connect(sockaddr)
    return sock


class DatagramQueue(object):
    """Datagrams between a flow's socket reader and its stream writer, up to a
    byte limit (each costs its length plus DATAGRAM_OVERHEAD, so empty ones
    count too). put never blocks: a full queue drops the datagram, as a full
    socket buffer would."""

    def __init__(self, limit):
        self.cond = threading.Condition()
        self.items = collections.deque()
        self.size = 0
        self.limit = limit
        self.dropped = 0
        self.closed = False

    def put(self, data):
        cost = len(data) + DATAGRAM_OVERHEAD
        with self.cond:
            if self.closed:
                return False
            if self.size + cost > self.limit:
                self.dropped += 1
                return False
            self.items.append(data)
            self.size += cost
            self.cond.notify()
            return True

    def get(self):
        """The next datagram, waiting for one; None once closed and empty."""
        with self.cond:
            while not self.items and not self.closed:
                self.cond.wait()
            if not self.items:
                return None
            data = self.items.popleft()
            self.size -= len(data) + DATAGRAM_OVERHEAD
            return data

    def close(self):
        with self.cond:
            self.closed = True
            self.cond.notify_all()


class FlowErrors(object):
    """The errors a flow carries on through, by direction and kind."""

    def __init__(self):
        self.lock = threading.Lock()
        self.counts = {}
        self.order = []

    def add(self, direction, err):
        """Counts err; True if it's the first of its kind."""
        errno_ = getattr(err, "errno", None)
        key = "%s: %s" % (direction, os.strerror(errno_) if errno_ else err)
        with self.lock:
            n = self.counts.get(key, 0) + 1
            self.counts[key] = n
            if n == 1:
                self.order.append(key)
        return n == 1

    def __str__(self):
        with self.lock:
            return ", ".join("%s (%d)" % (k, self.counts[k]) for k in self.order)


def handle_udp(st, addr):
    """One UDP flow: framed datagrams from the stream go to addr from a socket
    of our own, and what comes back goes into the stream, until subtun closes
    the stream. A reader drains the socket into a queue and a writer feeds the
    stream from it, so a slow stream doesn't overflow the socket. An error for
    one datagram (the ICMP errors a connected socket reports: port, host or
    network unreachable, too big for the path) doesn't end the flow: it's
    counted, and the first of each kind is logged."""
    try:
        host, port = split_host_port(addr)
        sock = udp_dial(host, port)
    except Exception as e:
        log("DEBUG", "udp dial failed", stream=st.sid, addr=addr, err=e)
        reply(st, status_for(e), "udp %s: %s" % (addr, e))
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_SOCKET_BUFFER)
    except OSError:
        pass
    sock.settimeout(1.0)  # the reader checks for the end at least this often
    counts = {"up": 0, "down": 0}
    start = time.time()
    closing = threading.Event()
    errs = FlowErrors()
    queue = DatagramQueue(UDP_QUEUE_BYTES)
    why = []  # why the flow ended: the first to say wins

    def note(direction, err):
        if errs.add(direction, err):
            log("DEBUG", "udp flow error", stream=st.sid, dir=direction, err=err)

    def sock_to_queue():
        streak = 0
        try:
            while True:
                try:
                    data = sock.recv(MAX_DATAGRAM)
                except socket.timeout:
                    if closing.is_set():
                        break
                    continue
                except OSError as e:
                    if closing.is_set():
                        break
                    note("read", e)
                    streak += 1
                    if streak >= UDP_ERROR_STREAK:
                        why.append("%d read errors in a row" % streak)
                        break
                    continue
                if closing.is_set():
                    break  # after shutdown recv returns b"" for ever
                streak = 0
                queue.put(data)
        finally:
            queue.close()

    def queue_to_stream():
        try:
            while True:
                data = queue.get()
                if data is None:
                    break
                st.write(struct.pack(">H", len(data)) + data)
                counts["down"] += len(data)
        except Exception as e:
            why.append("stream write: %s" % e)
        finally:
            # If the reader ended the flow, subtun hears of it, and we stop
            # reading the stream without waiting for subtun's side.
            st.close_write()
            st.kill()

    reader = threading.Thread(target=sock_to_queue)
    reader.daemon = True
    writer = threading.Thread(target=queue_to_stream)
    writer.daemon = True
    try:
        reply(st, ST_OK)
        reader.start()
        writer.start()
        while True:
            try:
                n, = struct.unpack(">H", st.read_exact(2, None))
                data = st.read_exact(n, None) if n else b""
            except EOFError:
                why.append("closed by subtun")
                break
            except IOError as e:
                why.append("stream read: %s" % e)
                break
            try:
                sock.send(data)
            except OSError as e:
                note("write", e)  # dropped, as UDP would
                continue
            counts["up"] += n
    finally:
        closing.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        st.kill()  # a writer waiting on the stream's window gives up
        for t in (reader, writer):
            if t.is_alive():
                t.join(5)
        sock.close()
    kv = dict(stream=st.sid, reason=why[0] if why else "unknown", up=counts["up"], down=counts["down"],
              dur="%.3fs" % (time.time() - start))
    if queue.dropped:
        kv["dropped"] = queue.dropped
    if str(errs):
        kv["errors"] = str(errs)
    log("DEBUG", "udp flow closed", **kv)


def is_ip(s):
    for family, text in ((socket.AF_INET, s), (socket.AF_INET6, s.split("%")[0])):
        try:
            socket.inet_pton(family, text)
            return True
        except (OSError, ValueError):
            pass
    return False


def nameservers():
    out = []
    with open(RESOLV_CONF) as f:
        for line in f:
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "nameserver" and is_ip(fields[1]):
                out.append(fields[1])
                if len(out) == MAX_NAMESERVERS:
                    break
    if not out:
        raise IOError("no nameserver in %s" % RESOLV_CONF)
    return out


def exchange_any(query):
    # Each server in turn: UDP first, TCP if the answer was truncated.
    deadline = time.time() + DNS_TOTAL_TIMEOUT
    last = None
    for server in nameservers():
        if time.time() >= deadline:
            break
        try:
            answer = dns_exchange(server, socket.SOCK_DGRAM, query, DNS_UDP_TIMEOUT)
            if truncated(answer):
                answer = dns_exchange(server, socket.SOCK_STREAM, query, DNS_TCP_TIMEOUT)
            return answer
        except Exception as e:
            last = e
            log("DEBUG", "DNS server failed", server=server, err=e)
    raise last or IOError("no nameserver answered")


def dns_connect(server, kind, timeout):
    # A connected socket to server port 53; kind is SOCK_DGRAM or SOCK_STREAM.
    family, kind, proto, _, addr = socket.getaddrinfo(server, 53, 0, kind)[0]
    sock = socket.socket(family, kind, proto)
    sock.settimeout(timeout)
    try:
        sock.connect(addr)
    except Exception:
        sock.close()
        raise
    return sock


def dns_exchange(server, kind, query, timeout):
    sock = dns_connect(server, kind, timeout)
    try:
        if kind == socket.SOCK_STREAM:
            sock.sendall(struct.pack(">H", len(query)) + query)
            n, = struct.unpack(">H", recv_exact(sock, 2))
            answer = recv_exact(sock, n)
            if not answers(answer, query):
                raise IOError("answer does not match the query")
            return answer
        sock.send(query)
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise socket.timeout("timed out")
            sock.settimeout(left)
            answer = sock.recv(65535)
            if answers(answer, query):  # skip stray datagrams
                return answer
    finally:
        sock.close()


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        data = sock.recv(n - len(buf))
        if not data:
            raise EOFError("connection closed")
        buf += data
    return buf


def answers(msg, query):
    return len(msg) >= MIN_DNS and msg[:2] == query[:2] and msg[2] & 0x80 != 0


def truncated(msg):
    return len(msg) >= MIN_DNS and msg[2] & 0x02 != 0


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
