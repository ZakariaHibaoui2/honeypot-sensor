"""Run several emulated services on one asyncio loop."""
from __future__ import annotations

import asyncio
import contextlib

from .events import Sink
from .services import HANDLERS, Limits, Session


class Honeypot:
    def __init__(self, sink: Sink, host: str = "127.0.0.1", ports: dict[str, int] | None = None,
                 limits: Limits | None = None):
        self.sink, self.host = sink, host
        self.ports = ports or {}
        self.limits = limits or Limits()
        self.servers: list[asyncio.base_events.Server] = []
        self.bound: dict[str, int] = {}

    def _handler(self, service: str):
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            s = Session(service, reader, writer, self.sink, self.limits)
            if self.limits.active[s.ip] >= self.limits.max_conns_per_ip:
                s.log("rejected", reason="too many concurrent connections")
                writer.close()
                return
            self.limits.active[s.ip] += 1
            s.log("connect")
            try:
                await HANDLERS[service](s)
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                self.limits.active[s.ip] -= 1
                s.log("disconnect")
                with contextlib.suppress(Exception):
                    writer.close()
                    await writer.wait_closed()
        return handle

    async def start(self) -> dict[str, int]:
        for service, port in self.ports.items():
            if service not in HANDLERS:
                raise ValueError(f"unknown service {service}")
            srv = await asyncio.start_server(self._handler(service), self.host, port, limit=self.limits.max_bytes * 4)
            self.servers.append(srv)
            self.bound[service] = srv.sockets[0].getsockname()[1]
        return self.bound

    async def stop(self) -> None:
        for srv in self.servers:
            srv.close()
            await srv.wait_closed()

    async def serve_forever(self) -> None:
        await self.start()
        await asyncio.gather(*(srv.serve_forever() for srv in self.servers))
