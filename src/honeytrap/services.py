"""Protocol emulators. They only *look* like real services: nothing is ever executed or proxied."""
from __future__ import annotations

import asyncio
import itertools
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote_plus

from .events import Event, Sink, clean

_session_ids = itertools.count(1)

LOGIN_PAGE = b"""<!doctype html><html><head><title>Admin Login</title></head><body>
<h2>Router Administration</h2><form method="post" action="/login">
<input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password">
<button>Sign in</button></form></body></html>"""


@dataclass
class Limits:
    read_timeout: float = 30.0
    max_bytes: int = 4096
    max_lines: int = 50
    max_conns_per_ip: int = 10
    active: Counter = field(default_factory=Counter)


class Session:
    def __init__(self, service: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, sink: Sink,
                 limits: Limits):
        peer = writer.get_extra_info("peername") or ("?", 0)
        self.service, self.reader, self.writer, self.sink, self.limits = service, reader, writer, sink, limits
        self.ip, self.port = str(peer[0]), int(peer[1])
        self.id = f"{service}-{next(_session_ids)}"

    def log(self, event: str, **data) -> None:
        self.sink.emit(Event(self.service, event, self.ip, self.port, self.id, data=data))

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def readline(self) -> bytes | None:
        try:
            line = await asyncio.wait_for(self.reader.readline(), self.limits.read_timeout)
        except (TimeoutError, asyncio.LimitOverrunError, ConnectionError):
            return None
        return line[: self.limits.max_bytes] if line else None


async def ssh(s: Session) -> None:
    await s.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")
    banner = await s.readline()
    if banner:
        s.log("banner", client_version=clean(banner.strip()))   # fingerprints the attacking tool/library


async def telnet(s: Session) -> None:
    await s.send(b"\r\nUbuntu 22.04.4 LTS\r\nweb01 login: ")
    for _ in range(3):
        user = await s.readline()
        if user is None:
            return
        await s.send(b"Password: ")
        pw = await s.readline()
        if pw is None:
            return
        s.log("login", username=clean(user.strip(), 64), password=clean(pw.strip(), 64), success=False)
        await s.send(b"\r\nLogin incorrect\r\nweb01 login: ")


async def ftp(s: Session) -> None:
    await s.send(b"220 (vsFTPd 3.0.5)\r\n")
    user = ""
    for _ in range(s.limits.max_lines):
        line = await s.readline()
        if line is None:
            return
        cmd, _, arg = clean(line.strip(), 256).partition(" ")
        cmd = cmd.upper()
        if cmd == "USER":
            user = arg
            await s.send(b"331 Please specify the password.\r\n")
        elif cmd == "PASS":
            s.log("login", username=user, password=arg[:64], success=False)
            await s.send(b"530 Login incorrect.\r\n")
        elif cmd == "QUIT":
            await s.send(b"221 Goodbye.\r\n")
            return
        else:
            s.log("command", command=cmd, argument=arg[:128])
            await s.send(b"530 Please login with USER and PASS.\r\n")


async def http(s: Session) -> None:
    request_line = await s.readline()
    if not request_line:
        return
    headers: dict[str, str] = {}
    for _ in range(s.limits.max_lines):
        line = await s.readline()
        if not line or line in (b"\r\n", b"\n"):
            break
        k, _, v = clean(line.strip(), 1024).partition(":")
        headers[k.strip().lower()] = v.strip()
    parts = clean(request_line.strip(), 1024).split(" ")
    method, path = (parts + ["", ""])[:2]
    body = b""
    length = min(int(headers.get("content-length", "0") or 0) if headers.get("content-length", "0").isdigit() else 0,
                 s.limits.max_bytes)
    if length:
        try:
            body = await asyncio.wait_for(s.reader.readexactly(length), s.limits.read_timeout)
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            body = b""
    s.log("request", method=method, path=path, user_agent=headers.get("user-agent", ""), host=headers.get("host", ""))
    if method == "POST" and body:
        form = parse_qs(body.decode("utf-8", "replace"))
        user = clean(unquote_plus(form.get("username", [""])[0]), 64)
        pw = clean(unquote_plus(form.get("password", [""])[0]), 64)
        if user or pw:
            s.log("login", username=user, password=pw, success=False, path=path)
        status, payload = b"401 Unauthorized", b"<h3>Invalid credentials</h3>"
    else:
        status, payload = b"200 OK", LOGIN_PAGE
    await s.send(b"HTTP/1.1 " + status + b"\r\nServer: lighttpd/1.4.59\r\nContent-Type: text/html\r\n"
                 + b"Content-Length: " + str(len(payload)).encode() + b"\r\nConnection: close\r\n\r\n" + payload)


HANDLERS = {"ssh": ssh, "telnet": telnet, "ftp": ftp, "http": http}
DEFAULT_PORTS = {"ssh": 2222, "telnet": 2323, "ftp": 2121, "http": 8080}
