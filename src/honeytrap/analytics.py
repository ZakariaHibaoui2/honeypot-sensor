"""Turn raw honeypot events into threat intelligence."""
from __future__ import annotations

import re
from collections import Counter, defaultdict

TOOLS = [
    (re.compile(r"libssh|paramiko|asyncssh|go\b|golang", re.I), "scripted SSH client"),
    (re.compile(r"PUTTY|OpenSSH", re.I), "interactive SSH client"),
    (re.compile(r"zgrab|masscan|nmap|nuclei|sqlmap|nikto|gobuster|dirbuster|wpscan|censys|shodan", re.I), "scanner"),
    (re.compile(r"curl|wget|python-requests|go-http-client|okhttp", re.I), "script / HTTP library"),
    (re.compile(r"\b(mozi|mirai|hajime)\b", re.I), "IoT botnet"),
]
SENSITIVE_PATHS = re.compile(r"(\.env|\.git|wp-login|wp-admin|phpmyadmin|/cgi-bin/|/boaform|/HNAP1|/shell|"
                             r"\.\./|/etc/passwd|setup\.cgi|/actuator|/console|/manager/html)", re.I)


def classify_tool(text: str) -> str:
    for rx, label in TOOLS:
        if rx.search(text or ""):
            return label
    return "unknown"


def summarize(events: list[dict], top: int = 10) -> dict:
    ips, services, users, passwords, pairs, paths, agents, hours = (Counter() for _ in range(8))
    tools: Counter = Counter()
    per_ip_logins: dict[str, int] = defaultdict(int)
    for e in events:
        ip, svc, kind, data = e["src_ip"], e["service"], e["event"], e.get("data", {})
        hours[e["timestamp"][:13]] += kind == "connect"
        if kind == "connect":
            ips[ip] += 1
            services[svc] += 1
        elif kind == "login":
            users[data.get("username", "")] += 1
            passwords[data.get("password", "")] += 1
            pairs[f"{data.get('username', '')}:{data.get('password', '')}"] += 1
            per_ip_logins[ip] += 1
        elif kind == "request":
            paths[data.get("path", "")] += 1
            agents[data.get("user_agent", "")] += 1
            tools[classify_tool(data.get("user_agent", ""))] += 1
        elif kind == "banner":
            agents[data.get("client_version", "")] += 1
            tools[classify_tool(data.get("client_version", ""))] += 1

    techniques = Counter()
    if any(n >= 3 for n in per_ip_logins.values()):
        techniques["T1110 Brute Force"] = sum(n for n in per_ip_logins.values() if n >= 3)
    if paths:
        techniques["T1595 Active Scanning"] = sum(paths.values())
    probes = {p: n for p, n in paths.items() if SENSITIVE_PATHS.search(p)}
    if probes:
        techniques["T1190 Exploit Public-Facing Application (probes)"] = sum(probes.values())

    return {
        "events": len(events),
        "connections": sum(ips.values()),
        "unique_ips": len(ips),
        "services": dict(services.most_common()),
        "top_ips": ips.most_common(top),
        "top_usernames": users.most_common(top),
        "top_passwords": passwords.most_common(top),
        "top_credential_pairs": pairs.most_common(top),
        "top_paths": paths.most_common(top),
        "sensitive_probes": sorted(probes.items(), key=lambda kv: -kv[1])[:top],
        "client_fingerprints": agents.most_common(top),
        "tool_classes": dict(tools.most_common()),
        "mitre": dict(techniques.most_common()),
        "activity_by_hour": dict(sorted(hours.items())),
    }


def render(summary: dict) -> str:
    def block(title: str, rows: list) -> list[str]:
        if not rows:
            return []
        return [f"\n{title}"] + [f"  {n:>5}  {k}" for k, n in rows]

    lines = [f"{summary['events']} events, {summary['connections']} connections from {summary['unique_ips']} IPs",
             f"services: {summary['services']}"]
    lines += block("Top attacking IPs", summary["top_ips"])
    lines += block("Top usernames", summary["top_usernames"])
    lines += block("Top passwords", summary["top_passwords"])
    lines += block("Top credential pairs", summary["top_credential_pairs"])
    lines += block("Sensitive path probes", summary["sensitive_probes"])
    lines += block("Client fingerprints", summary["client_fingerprints"])
    lines += block("Tool classes", list(summary["tool_classes"].items()))
    lines += block("MITRE ATT&CK", list(summary["mitre"].items()))
    return "\n".join(lines)
