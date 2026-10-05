"""honeytrap command line: run the sensor, analyse logs, or run a self-contained demo."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .analytics import render, summarize
from .events import Sink, load
from .server import Honeypot
from .services import DEFAULT_PORTS


def _ports(spec: list[str] | None) -> dict[str, int]:
    if not spec:
        return dict(DEFAULT_PORTS)
    out = {}
    for item in spec:
        name, _, port = item.partition("=")
        out[name] = int(port) if port else DEFAULT_PORTS[name]
    return out


async def _demo(log: str | None) -> dict:
    from .simulate import run

    sink = Sink(log)
    pot = Honeypot(sink, "127.0.0.1", {s: 0 for s in DEFAULT_PORTS})
    ports = await pot.start()
    await run("127.0.0.1", ports, rounds=25)
    await pot.stop()
    return summarize([e.__dict__ for e in sink.events])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="honeytrap", description="Low-interaction honeypot sensor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="start the sensor")
    r.add_argument("--host", default="127.0.0.1", help="bind address (use 0.0.0.0 only on an isolated host)")
    r.add_argument("--service", action="append", help="service[=port], e.g. ssh=2222 (repeatable)")
    r.add_argument("--log", default="honeytrap.jsonl")
    rep = sub.add_parser("report", help="summarise a JSON-lines log")
    rep.add_argument("log")
    rep.add_argument("--json", action="store_true")
    d = sub.add_parser("demo", help="start all services on localhost, replay simulated attacks, print the report")
    d.add_argument("--log")
    a = ap.parse_args(argv)

    if a.cmd == "run":
        ports = _ports(a.service)
        pot = Honeypot(Sink(a.log), a.host, ports)
        print(f"honeytrap listening on {a.host}: {ports}  ->  {a.log}  (Ctrl+C to stop)")
        try:
            asyncio.run(pot.serve_forever())
        except KeyboardInterrupt:
            pass
        return 0
    if a.cmd == "report":
        s = summarize(load(a.log))
        print(json.dumps(s, indent=2) if a.json else render(s))
        return 0
    print(render(asyncio.run(_demo(a.log))))
    return 0


def entrypoint() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())


if __name__ == "__main__":
    entrypoint()
