"""Attack traffic simulator: drives a running honeypot like real bots do (for demos and tests)."""
from __future__ import annotations

import asyncio
import random

CREDS = [("root", "root"), ("admin", "admin"), ("root", "123456"), ("admin", "password"), ("ubuntu", "ubuntu"),
         ("pi", "raspberry"), ("root", "toor"), ("user", "user"), ("support", "support"), ("admin", "1234")]
PATHS = ["/", "/.env", "/wp-login.php", "/phpmyadmin/", "/.git/config", "/cgi-bin/luci", "/boaform/admin/formLogin",
         "/HNAP1/", "/actuator/env", "/manager/html", "/admin", "/login"]
UAS = ["Mozilla/5.0 zgrab/0.x", "curl/8.4.0", "python-requests/2.31", "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
       "Go-http-client/1.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"]
SSH_CLIENTS = ["SSH-2.0-Go", "SSH-2.0-libssh_0.9.6", "SSH-2.0-paramiko_3.4.0", "SSH-2.0-PUTTY", "SSH-2.0-OpenSSH_9.6"]


async def _conn(host: str, port: int):
    return await asyncio.wait_for(asyncio.open_connection(host, port), 5)


async def ssh_probe(host, port, rng):
    r, w = await _conn(host, port)
    await r.readline()
    w.write(rng.choice(SSH_CLIENTS).encode() + b"\r\n")
    await w.drain()
    w.close()


async def telnet_bruteforce(host, port, rng, attempts=3):
    r, w = await _conn(host, port)
    for user, pw in rng.sample(CREDS, attempts):
        await r.readuntil(b"login: ")
        w.write(user.encode() + b"\r\n")
        await r.readuntil(b"Password: ")
        w.write(pw.encode() + b"\r\n")
        await w.drain()
    await r.readuntil(b"login: ")
    w.close()


async def ftp_bruteforce(host, port, rng, attempts=2):
    r, w = await _conn(host, port)
    await r.readline()
    for user, pw in rng.sample(CREDS, attempts):
        w.write(f"USER {user}\r\n".encode())
        await r.readline()
        w.write(f"PASS {pw}\r\n".encode())
        await r.readline()
    w.write(b"QUIT\r\n")
    await r.readline()
    w.close()


async def http_probe(host, port, rng):
    r, w = await _conn(host, port)
    if rng.random() < 0.3:
        user, pw = rng.choice(CREDS)
        body = f"username={user}&password={pw}".encode()
        w.write(b"POST /login HTTP/1.1\r\nHost: x\r\nUser-Agent: " + rng.choice(UAS).encode()
                + b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body)
    else:
        w.write(f"GET {rng.choice(PATHS)} HTTP/1.1\r\nHost: x\r\nUser-Agent: {rng.choice(UAS)}\r\n\r\n".encode())
    await w.drain()
    await r.read()
    w.close()


async def run(host: str, ports: dict[str, int], rounds: int = 20, seed: int = 1) -> None:
    rng = random.Random(seed)
    tasks = []
    for _ in range(rounds):
        if "ssh" in ports:
            tasks.append(ssh_probe(host, ports["ssh"], rng))
        if "telnet" in ports:
            tasks.append(telnet_bruteforce(host, ports["telnet"], rng))
        if "ftp" in ports:
            tasks.append(ftp_bruteforce(host, ports["ftp"], rng))
        if "http" in ports:
            tasks.append(http_probe(host, ports["http"], rng))
    sem = asyncio.Semaphore(5)   # stay under the per-IP connection cap

    async def guarded(coro):
        async with sem:
            await coro
    await asyncio.gather(*(guarded(t) for t in tasks))
    await asyncio.sleep(0.2)
