# Test shim, run in the agent's globals after agent.py: replaces dial() and
# dns_connect() with in-process socket pairs (no network), then starts the
# agent.
import errno
import os
import socket
import struct
import threading


def _echo(s):
    try:
        while True:
            data = s.recv(65536)
            if not data:
                break
            s.sendall(data)
        s.shutdown(socket.SHUT_WR)
    finally:
        s.close()


def _reply_after_eof(s):
    try:
        got = b""
        while True:
            data = s.recv(65536)
            if not data:
                break
            got += data
        s.sendall(b"got:" + got)
    finally:
        s.close()


def _wait_eof(s):
    try:
        while s.recv(65536):
            pass
    except OSError:
        pass
    finally:
        s.close()


class _Failing(object):
    """Wraps a socket: recv fails with errs first, one per call, then works;
    with forever set, every recv fails."""

    def __init__(self, sock, errs=(), forever=None):
        self._sock = sock
        self._errs = list(errs)
        self._forever = forever

    def recv(self, n, flags=0):
        if self._forever is not None:
            raise OSError(self._forever, os.strerror(self._forever))
        if self._errs:
            e = self._errs.pop(0)
            if e == errno.ECONNRESET:
                raise ConnectionResetError(e, os.strerror(e))
            raise OSError(e, os.strerror(e))
        return self._sock.recv(n, flags)

    def __getattr__(self, name):
        return getattr(self._sock, name)


def _blob(s):
    # 1 MiB at once (the socket buffers hold it all), then EOF.
    try:
        s.sendall(bytes(1 << 20))
        s.shutdown(socket.SHUT_WR)
        while s.recv(65536):
            pass
    except OSError:
        pass
    finally:
        s.close()


_HANDLERS = {"echo.svc:7": _echo, "rr.svc:80": _reply_after_eof, "reset.svc:80": _wait_eof, "blob.svc:80": _blob}
_FAIL_TCP = {"reset.svc:80": dict(errs=[errno.ECONNRESET])}


def dial(host, port):
    key = "%s:%d" % (host, port)
    handler = _HANDLERS.get(key)
    if handler is None:
        raise ConnectionRefusedError(errno.ECONNREFUSED, "connection refused")
    a, b = socket.socketpair()
    if handler is _blob:
        a.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        b.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    t = threading.Thread(target=handler, args=(b,))
    t.daemon = True
    t.start()
    if key in _FAIL_TCP:
        return _Failing(a, **_FAIL_TCP[key])
    return a


def _dns_answer(query, marker, tc=False):
    flags = query[2] | 0x80 | (0x02 if tc else 0)
    return query[:2] + bytes([flags]) + query[3:] + marker


def _dns_udp(s):
    # Answers one datagram; a stray answer with the wrong ID goes first.
    # Names starting with "big" get a truncated answer.
    try:
        q = s.recv(512)
        stray = _dns_answer(q, b"stray")
        s.send(bytes([stray[0] ^ 0xFF]) + stray[1:])
        s.send(_dns_answer(q, b"udp", tc=b"\x03big" in q))
    finally:
        s.close()


def _dns_tcp(s):
    try:
        n = struct.unpack(">H", recv_exact(s, 2))[0]
        a = _dns_answer(recv_exact(s, n), b"tcp")
        s.sendall(struct.pack(">H", len(a)) + a)
    finally:
        s.close()


_DNS = {("10.96.0.10", socket.SOCK_DGRAM): _dns_udp, ("10.96.0.10", socket.SOCK_STREAM): _dns_tcp}


def dns_connect(server, kind, timeout):
    handler = _DNS.get((server, kind))
    if handler is None:
        raise ConnectionRefusedError(errno.ECONNREFUSED, "connection refused")
    a, b = socket.socketpair(socket.AF_UNIX, kind)
    a.settimeout(timeout)
    t = threading.Thread(target=handler, args=(b,))
    t.daemon = True
    t.start()
    return a


def _udp_echo(s):
    # Answers each datagram with "re:" + it (an empty one too), until the
    # agent shuts its end.
    try:
        while True:
            data = s.recv(65535)
            s.send(b"re:" + data)
    except OSError:
        pass
    finally:
        s.close()


_UDP = {"dns.svc:53": _udp_echo, "quic.svc:443": _udp_echo, "dead.svc:9": _udp_echo}
# ICMP errors for earlier datagrams, as a connected UDP socket reports them.
_FAIL_UDP = {
    "quic.svc:443": dict(errs=[errno.EHOSTUNREACH, errno.EMSGSIZE, errno.EHOSTUNREACH, errno.ECONNREFUSED]),
    "dead.svc:9": dict(forever=errno.ENETUNREACH),
}


_real_udp_dial = udp_dial


def udp_dial(host, port):
    if host == "127.0.0.1":
        return _real_udp_dial(host, port)  # a real socket: the throughput test
    key = "%s:%d" % (host, port)
    handler = _UDP.get(key)
    if handler is None:
        raise ConnectionRefusedError(errno.ECONNREFUSED, "connection refused")
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    t = threading.Thread(target=handler, args=(b,))
    t.daemon = True
    t.start()
    if key in _FAIL_UDP:
        return _Failing(a, **_FAIL_UDP[key])
    return a


main()
