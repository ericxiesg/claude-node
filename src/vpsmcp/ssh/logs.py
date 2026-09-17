"""Log subscriptions: a long-lived tail -F / journalctl -f feeding a ring buffer.

MCP has no server-push channel, so this is pull-based: log_open starts collecting
on the gateway, log_read fetches new lines by cursor.
"""
from __future__ import annotations

import asyncio
import re
import shlex
import time
import uuid
from collections import deque
from dataclasses import dataclass, field


class LogError(RuntimeError):
    pass


@dataclass
class LogSub:
    id: str
    alias: str
    node_id: str
    source: str
    process: object
    buf: deque = field(default_factory=lambda: deque(maxlen=5000))
    seq: int = 0
    task: asyncio.Task | None = None
    created: float = field(default_factory=time.time)
    last_read: float = field(default_factory=time.time)
    dropped: int = 0
    closed: bool = False


class LogManager:
    def __init__(self, pool, max_subs: int = 16, buffer_lines: int = 5000):
        self.pool = pool
        self.max_subs = max_subs
        self.buffer_lines = buffer_lines
        self._subs: dict[str, LogSub] = {}

    async def open(self, host, inv, *, path: str | None = None, unit: str | None = None,
                   grep: str | None = None, initial_lines: int = 50) -> LogSub:
        if len([s for s in self._subs.values() if not s.closed]) >= self.max_subs:
            raise LogError(f"subscription limit {self.max_subs} reached")
        if bool(path) == bool(unit):
            raise LogError("provide exactly one of path or unit")
        if grep:
            re.compile(grep)  # validate before sending to the remote
        if unit:
            cmd = (f"journalctl --no-pager -o short-iso -n {int(initial_lines)} -f "
                   f"-u {shlex.quote(unit)}")
            source = f"unit:{unit}"
        else:
            cmd = f"tail -n {int(initial_lines)} -F -- {shlex.quote(path)}"
            source = f"file:{path}"
        if grep:
            cmd += f" | grep --line-buffered -E {shlex.quote(grep)}"
        cmd = f"stdbuf -oL -eL {cmd} 2>&1" if unit is None else f"{cmd} 2>&1"

        conn = await self.pool.acquire(host, inv)
        proc = await conn.create_process(f"bash -lc {shlex.quote(cmd)}",
                                         term_type=None, encoding="utf-8", errors="replace")
        sub = LogSub(id=f"log_{uuid.uuid4().hex[:10]}", alias=host.alias, node_id=host.node_id,
                     source=source, process=proc)
        sub.buf = deque(maxlen=self.buffer_lines)
        self._subs[sub.id] = sub
        self.pool.pin(host.node_id)
        sub.task = asyncio.create_task(self._pump(sub))
        return sub

    async def _pump(self, sub: LogSub) -> None:
        try:
            while True:
                line = await sub.process.stdout.readline()
                if not line:
                    break
                if len(sub.buf) == sub.buf.maxlen:
                    sub.dropped += 1
                sub.seq += 1
                sub.buf.append((sub.seq, time.time(), line.rstrip("\n")))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            sub.seq += 1
            sub.buf.append((sub.seq, time.time(), f"[vpsmcp] collection stopped: {exc}"))
        finally:
            sub.closed = True

    def read(self, sub_id: str, since_seq: int = 0, limit: int = 300) -> dict:
        sub = self._subs.get(sub_id)
        if sub is None:
            raise LogError(f"subscription {sub_id} not found")
        sub.last_read = time.time()
        rows = [r for r in sub.buf if r[0] > since_seq][:limit]
        return {
            "sub_id": sub_id,
            "host": sub.alias,
            "source": sub.source,
            "closed": sub.closed,
            "dropped_lines": sub.dropped,
            "next_seq": rows[-1][0] if rows else since_seq,
            "latest_seq": sub.seq,
            "lines": [{"seq": s, "ts": round(t, 3), "text": x} for s, t, x in rows],
        }

    async def close(self, sub_id: str) -> None:
        sub = self._subs.pop(sub_id, None)
        if not sub:
            return
        sub.closed = True
        if sub.task:
            sub.task.cancel()
        try:
            sub.process.kill()
        except Exception:  # noqa: BLE001
            pass
        try:
            sub.process.close()
        except Exception:  # noqa: BLE001
            pass
        self.pool.unpin(sub.node_id)

    def list(self) -> list[dict]:
        now = time.time()
        return [
            {"sub_id": s.id, "host": s.alias, "source": s.source, "buffered": len(s.buf),
             "latest_seq": s.seq, "dropped": s.dropped, "closed": s.closed,
             "idle_s": round(now - s.last_read, 1)}
            for s in self._subs.values()
        ]

    async def close_all(self) -> None:
        for sid in list(self._subs):
            await self.close(sid)
