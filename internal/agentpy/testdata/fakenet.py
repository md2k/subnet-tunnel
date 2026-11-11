# Test shim, run in the agent's globals after agent.py: replaces dial() with
# in-process socket pairs (no network), then starts the agent.
import errno
import socket
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


main()
