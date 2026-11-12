# Test shim, run in the agent's globals after agent.py: replaces dial() and
# dns_connect() with in-process socket pairs (no network), then starts the
# agent.
import errno
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


_HANDLERS = {"echo.svc:7": _echo, "rr.svc:80": _reply_after_eof}


def dial(host, port):
    handler = _HANDLERS.get("%s:%d" % (host, port))
    if handler is None:
        raise ConnectionRefusedError(errno.ECONNREFUSED, "connection refused")
    a, b = socket.socketpair()
    t = threading.Thread(target=handler, args=(b,))
    t.daemon = True
    t.start()
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


main()
