import asyncio
import json

import pytest

from honeytrap.analytics import classify_tool, summarize
from honeytrap.cli import main
from honeytrap.events import Sink, clean, load
from honeytrap.server import Honeypot
from honeytrap.services import Limits
from honeytrap.simulate import run


def test_clean_neutralises_control_chars():
    assert clean(b"root\x1b[31m\x00") == "root\\x1b[31m\\x00"
    assert len(clean("a" * 5000)) == 512


@pytest.mark.parametrize("ua,label", [("SSH-2.0-libssh_0.9.6", "scripted SSH client"), ("zgrab/0.x", "scanner"),
                                      ("curl/8.4", "script / HTTP library"), ("Mozilla/5.0 Chrome", "unknown"),
                                      ("Mozi.m", "IoT botnet"), ("mirai.arm7", "IoT botnet")])
def test_tool_classification(ua, label):
    assert classify_tool(ua) == label


async def _with_pot(fn, limits=None, log=None):
    sink = Sink(log)
    pot = Honeypot(sink, "127.0.0.1", {"ssh": 0, "telnet": 0, "ftp": 0, "http": 0}, limits)
    ports = await pot.start()
    try:
        await fn(ports)
    finally:
        await pot.stop()
    return sink.events


def test_ssh_banner_capture():
    async def go(ports):
        r, w = await asyncio.open_connection("127.0.0.1", ports["ssh"])
        assert (await r.readline()).startswith(b"SSH-2.0-OpenSSH")
        w.write(b"SSH-2.0-paramiko_3.4.0\r\n")
        await w.drain()
        await r.read()
        w.close()
    events = asyncio.run(_with_pot(go))
    banners = [e for e in events if e.event == "banner"]
    assert banners and banners[0].data["client_version"] == "SSH-2.0-paramiko_3.4.0"


def test_telnet_credentials_captured_and_never_accepted():
    async def go(ports):
        r, w = await asyncio.open_connection("127.0.0.1", ports["telnet"])
        await r.readuntil(b"login: ")
        w.write(b"root\r\n")
        await r.readuntil(b"Password: ")
        w.write(b"toor\r\n")
        assert b"Login incorrect" in await r.readuntil(b"login: ")
        w.close()
    events = asyncio.run(_with_pot(go))
    logins = [e.data for e in events if e.event == "login"]
    assert logins == [{"username": "root", "password": "toor", "success": False}]


def test_http_login_form_capture():
    async def go(ports):
        r, w = await asyncio.open_connection("127.0.0.1", ports["http"])
        body = b"username=admin&password=hunter2"
        w.write(b"POST /login HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body)
        await w.drain()
        assert b"401 Unauthorized" in await r.read()
        w.close()
    events = asyncio.run(_with_pot(go))
    assert any(e.event == "login" and e.data["password"] == "hunter2" for e in events)
    assert any(e.event == "request" and e.data["user_agent"] == "curl/8" for e in events)


def test_per_ip_connection_cap():
    async def go(ports):
        conns = [await asyncio.open_connection("127.0.0.1", ports["telnet"]) for _ in range(4)]
        await asyncio.sleep(0.2)
        for _, w in conns:
            w.close()
        await asyncio.sleep(0.1)
    events = asyncio.run(_with_pot(go, Limits(max_conns_per_ip=2, read_timeout=2)))
    assert sum(e.event == "rejected" for e in events) == 2


def test_simulation_and_analytics(tmp_path):
    log = tmp_path / "h.jsonl"
    events = asyncio.run(_with_pot(lambda ports: run("127.0.0.1", ports, rounds=8), log=str(log)))
    assert len(load(log)) == len(events)
    s = summarize([e.__dict__ for e in events])
    assert set(s["services"]) == {"ssh", "telnet", "ftp", "http"}
    assert s["top_passwords"] and "T1110 Brute Force" in s["mitre"]
    assert s["connections"] == 32


def test_cli_report(tmp_path, capsys):
    log = tmp_path / "h.jsonl"
    asyncio.run(_with_pot(lambda ports: run("127.0.0.1", ports, rounds=3), log=str(log)))
    main(["report", str(log), "--json"])
    assert json.loads(capsys.readouterr().out)["unique_ips"] == 1
