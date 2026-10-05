# HoneyTrap — Low-Interaction Honeypot Sensor

> An asyncio honeypot that impersonates **SSH, Telnet, FTP and an HTTP router-admin page**. It records what attackers try (client fingerprints, credential guesses, commands, probed paths) as JSON events, then turns them into threat intelligence: top attackers, the most-tried passwords, tool classification and MITRE ATT&CK mapping.

[![CI](https://github.com/ZakariaHibaoui2/honeypot-sensor/actions/workflows/ci.yml/badge.svg)](https://github.com/ZakariaHibaoui2/honeypot-sensor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![asyncio](https://img.shields.io/badge/asyncio-concurrent-blue)
![Zero deps](https://img.shields.io/badge/dependencies-0-brightgreen)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Demo

`honeytrap demo` starts all four services on localhost, replays bot-like attacks against them (SSH tooling, Telnet/FTP brute force, web scanners, login-form spraying) and prints the analytics:

```text
383 events, 100 connections from 1 IPs
services: {'ssh': 25, 'telnet': 25, 'ftp': 25, 'http': 25}

Top credential pairs
     19  support:support
     16  admin:1234
     16  root:toor
     14  admin:password
     12  pi:raspberry

Sensitive path probes
      3  /.git/config
      2  /phpmyadmin/
      1  /HNAP1/
      1  /actuator/env
      1  /boaform/admin/formLogin

Client fingerprints
      8  Mozilla/5.0 (compatible; Nmap Scripting Engine)
      5  SSH-2.0-paramiko_3.4.0
      4  SSH-2.0-libssh_0.9.6
      3  Mozilla/5.0 zgrab/0.x

Tool classes
     14  scripted SSH client
     11  scanner
      8  script / HTTP library

MITRE ATT&CK
    133  T1110 Brute Force
     25  T1595 Active Scanning
     12  T1190 Exploit Public-Facing Application (probes)
```

## Emulated services

| Service | Default port | Captures |
|---|---|---|
| SSH | 2222 | Server banner `OpenSSH_8.9p1 Ubuntu`; the client version string fingerprints the attacking library (Go, libssh, paramiko…) |
| Telnet | 2323 | Login/password pairs (always "Login incorrect"), up to 3 tries per session |
| FTP | 2121 | `USER`/`PASS` credentials and other commands (vsFTPd banner) |
| HTTP | 8080 | Method, path, user-agent, host; a fake "Router Administration" form captures POSTed credentials |

## Safety by design

- **Nothing is ever executed, proxied or stored as a file.** Every response is canned text.
- Binds to **127.0.0.1 by default**. Expose it (`--host 0.0.0.0`) only on an isolated machine or VM with no production data.
- Per-IP concurrent-connection cap, read timeouts, a maximum bytes per read, and a maximum number of lines per session.
- Attacker input is sanitised before logging (control characters escaped, values truncated), so viewing logs in a terminal can't trigger escape-sequence tricks.
- Use high ports (defaults above) and map 22/23/21/80 to them with your firewall instead of running as root.

## Usage

```bash
pip install -e ".[dev]"
honeytrap demo                                          # self-contained demonstration
honeytrap run --service ssh=2222 --service http=8080 --log events.jsonl
honeytrap report events.jsonl                           # analytics
honeytrap report events.jsonl --json > intel.json
```

Event format (one JSON object per line):

```json
{"service": "telnet", "event": "login", "src_ip": "198.51.100.7", "src_port": 51544, "session": "telnet-12",
 "timestamp": "2026-10-05T17:20:31.512+00:00", "data": {"username": "root", "password": "toor", "success": false}}
```

These lines feed straight into the [mini-siem](https://github.com/ZakariaHibaoui2/mini-siem) or [log-anomaly-detector](https://github.com/ZakariaHibaoui2/log-anomaly-detector) projects.

```bash
docker build -t honeytrap . && docker run -p 2222:2222 -p 2323:2323 -p 2121:2121 -p 8080:8080 -v $PWD/logs:/logs honeytrap
```

## Project structure

```
src/honeytrap/
├── services.py    # SSH / Telnet / FTP / HTTP emulators + limits
├── server.py      # asyncio multi-service server, per-IP caps
├── events.py      # event model, sanitising, JSONL sink
├── analytics.py   # credentials, probes, fingerprints, tool classes, MITRE
├── simulate.py    # bot-like attack traffic generator
└── cli.py         # run · report · demo
tests/             # 13 tests on real sockets (localhost): every protocol, connection cap, analytics, CLI
```

> Deploy honeypots only on infrastructure you own and in line with local law and your provider's terms.

## License

[MIT](LICENSE)
