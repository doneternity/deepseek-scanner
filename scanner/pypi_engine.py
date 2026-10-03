import asyncio
import hashlib
import logging
import os
import re
import tempfile
import time
import xmlrpc.client

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.pkgscan import scan_archive
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.pypi")

PYPI_RPC = "https://pypi.org/pypi"


class PypiEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, stats=None, deny: frozenset[str] = frozenset(),
                 poll_interval: int = 120,
                 scan_terms: list[str] | None = None,
                 max_size_kb: int = 300, max_size_kb_term: int = 5000,
                 max_download_kb: int = 25000):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.stats = stats
        self.deny = deny
        self.poll_interval = poll_interval
        self.scan_terms = [t.lower() for t in (scan_terms or ["deepseek"])]
        self.max_size_kb = max_size_kb
        self.max_size_kb_term = max_size_kb_term
        self.max_download_kb = max_download_kb
        self.bucket = TokenBucket(rate=3.0, capacity=60)

    async def run(self):
        while True:
            try:
                await self.poll()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("pypi poll failed")
            await asyncio.sleep(self.poll_interval)

    async def poll(self):
        last_serial = int(self.store.kv_get("pypi_last_serial") or 0)
        try:
            serial, changes = await asyncio.to_thread(self._changelog, last_serial)
        except Exception as exc:
            log.warning("pypi changelog failed: %s", exc)
            return
        if serial:
            self.store.kv_set("pypi_last_serial", str(serial))
        if self.stats:
            mark_beat(self.stats, "pypi", self.poll_interval)
        if not changes:
            return
        if self.stats:
            self.stats.pypi_pkgs += len(changes)
        log.info("pypi: %d new releases", len(changes))
        seen = set()
        await asyncio.gather(
            *[self._process_release(name, version) for name, version, _, _, _ in changes
              if (name, version) not in seen and not seen.add((name, version))],
            return_exceptions=True,
        )

    @staticmethod
    def _changelog(last_serial: int) -> tuple[int, list]:
        proxy = xmlrpc.client.ServerProxy(PYPI_RPC)
        try:
            if last_serial == 0:
                return int(proxy.changelog_last_serial()), []
            raw = proxy.changelog_since_serial(last_serial)
        finally:
            try:
                proxy("close")()
            except Exception:
                pass
        entries = [(str(n), str(v), int(ts), str(a), int(s))
                   for n, v, ts, a, s in raw]
        serial = entries[-1][4] if entries else last_serial
        return serial, entries

    async def _process_release(self, name: str, version: str):
        try:
            resp = await self.client.get(
                f"https://pypi.org/pypi/{name}/{version}/json", timeout=30.0)
        except httpx.HTTPError:
            return
        if resp.status_code != 200:
            return
        try:
            data = resp.json()
        except ValueError:
            return

        urls = data.get("urls") or []
        desc = (data.get("info") or {}).get("description") or ""
        if desc:
            self._emit_text(name, version, "package description", desc)
        if not urls:
            return

        name_lower = name.lower()
        term_match = any(t in name_lower for t in self.scan_terms)
        cap = self.max_size_kb_term if term_match else self.max_size_kb

        pick = None
        for u in urls:
            if u.get("packagetype") == "sdist":
                pick = u
                break
        if pick is None:
            for u in urls:
                if u.get("packagetype") == "bdist_wheel":
                    pick = u
                    break
        if pick is None:
            return
        size = int(pick.get("size") or 0)
        if size and size > cap * 1024:
            return

        await self.bucket.acquire()
        fd, tmp = tempfile.mkstemp(suffix=".pkg")
        os.close(fd)
        limit_bytes = self.max_download_kb * 1024
        try:
            async with self.client.stream("GET", pick["url"], timeout=60.0,
                                          follow_redirects=True) as resp:
                if resp.status_code != 200:
                    return
                total = 0
                with open(tmp, "wb") as fh:
                    async for chunk in resp.aiter_bytes():
                        total += len(chunk)
                        if total > limit_bytes:
                            log.warning("pypi package too large, aborting: %s", name)
                            return
                        fh.write(chunk)
            matches = await asyncio.to_thread(scan_archive, tmp, self.pattern, self.deny)
        except httpx.HTTPError:
            return
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

        for path, key in matches:
            self._emit_key(name, version, path, key)

    async def _emit_text(self, name: str, version: str, path: str, text: str):
        for key in extract_keys(text, self.pattern):
            if is_placeholder(key, self.deny):
                continue
            self._emit_key(name, version, path, key)

    def _emit_key(self, name: str, version: str, path: str, key: str):
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        if not self.store.add_candidate(
            key_hash=key_hash,
            key=key,
            repo=name,
            file_path=path,
            commit_url=f"https://pypi.org/project/{name}/{version}/",
            author_name=None,
            author_email=None,
            source="pypi",
        ):
            return
        log.info("candidate from pypi: %s %s", name, path)
        if self.stats:
            self.stats.candidates += 1
        self.candidates.put_nowait({
            "key_hash": key_hash,
            "key": key,
            "repo": name,
            "file_path": path,
            "commit_url": f"https://pypi.org/project/{name}/{version}/",
            "author_name": None,
            "author_email": None,
            "source": "pypi",
            "priority": "hot",
        })
