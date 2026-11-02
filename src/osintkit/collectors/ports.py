"""Lightweight TCP connect probes against common ports."""

from __future__ import annotations

import asyncio

from ..http import cache_hit, cache_put
from .base import Context, collector

NAMESPACE = "ports"

PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

CONCURRENCY = 24
TIMEOUT = 2.5


async def _probe(host: str, port: int, service: str, semaphore: asyncio.Semaphore) -> dict | None:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TIMEOUT)
        except (TimeoutError, OSError):
            return None
        banner = ""
        try:
            banner_bytes = await asyncio.wait_for(reader.read(120), timeout=1.0)
            banner = banner_bytes.decode("utf-8", "replace").strip().splitlines()[0][:120]
        except (TimeoutError, OSError, IndexError):
            banner = ""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        return {"port": port, "service": service, "banner": banner or None}


@collector("tcp_ports", ("domain",), "Open TCP ports on common services", order=80, ttl=3600)
def selected_ports(override: list[str] | None) -> dict[int, str]:
    if not override:
        return dict(PORTS)
    chosen: dict[int, str] = {}
    for raw in override:
        port = int(raw)
        chosen[port] = PORTS.get(port, "unknown")
    return dict(sorted(chosen.items()))


async def tcp_ports(ctx: Context) -> dict:
    ports = selected_ports(ctx.settings.extra.get("ports"))
    host = ctx.target.lower()
    key = f"{host}|{','.join(str(port) for port in ports)}"
    cached = cache_hit(ctx.settings, NAMESPACE, key, ctx.cache_ttl)
    if cached is not None:
        return cached

    semaphore = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(*(_probe(host, port, service, semaphore) for port, service in ports.items()))
    open_ports = [r for r in results if r]
    payload = {
        "host": host,
        "scanned": len(ports),
        "open": sorted(open_ports, key=lambda r: r["port"]),
        "note": "single connect probe from the local network; filtered ports may be missed",
    }
    cache_put(ctx.settings, NAMESPACE, key, payload)
    return payload
