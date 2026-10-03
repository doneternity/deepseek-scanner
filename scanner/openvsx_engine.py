import asyncio
import hashlib
import logging
import os
import re
import tempfile

import httpx

from scanner.pkgscan import scan_archive
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.openvsx")

SEARCH_URL = "https://open-vsx.org/api/-/search"


class OpenVSXEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, queries: list[str] | None = None,
                 max_extensions: int = 30, max_download_kb: int = 25000,
                 interval_seconds: int = 43200, stats=None,
                 deny: frozenset[str] = frozenset()):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.queries = queries or ["deepseek", "deepseek api"]
        self.max_extensions = max_extensions
        self.max_download_kb = max_download_kb
        self.interval_seconds = interval_seconds
        self.stats = stats
        self.deny = deny
        self.bucket = TokenBucket(rate=0.5, capacity=5)

    async def run(self):
        while True:
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("openvsx sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        extensions: list[tuple[str, str, str, str]] = []
        seen: set[tuple[str, str]] = set()
        for query in self.queries:
            if self.stats:
                mark_beat(self.stats, "openvsx", self.interval_seconds)
            await self.bucket.acquire()
            try:
                resp = await self.client.get(
                    SEARCH_URL, params={"query": query, "size": 100, "offset": 0},
                    headers={"User-Agent": "deepseek-scanner"}, timeout=30.0)
            except httpx.HTTPError as exc:
                log.warning("openvsx search failed: %s", exc)
                continue
            if resp.status_code != 200:
                log.warning("openvsx search HTTP %d for %r", resp.status_code, query)
                continue
            try:
                items = resp.json().get("extensions") or []
            except ValueError:
                continue
            for item in items:
                ns = item.get("namespace")
                name = item.get("name")
                version = item.get("version")
                download = (item.get("files") or {}).get("download")
                if not (ns and name and version and download):
                    continue
                key = (ns, name)
                if key in seen:
                    continue
                seen.add(key)
                extensions.append((ns, name, version, download))
        if self.stats:
            self.stats.openvsx_ext += len(extensions)
        log.info("openvsx: %d extensions to inspect", len(extensions))

        count = 0
        for ns, name, version, download in extensions:
            if count >= self.max_extensions:
                break
            if self.store.file_seen("openvsx", f"{ns}/{name}", version):
                continue
            count += 1
            try:
                await self._scan_extension(ns, name, version, download)
            except Exception:
                log.exception("openvsx extension scan failed: %s.%s", ns, name)

    async def _scan_extension(self, ns: str, name: str, version: str,
                              download: str):
        await self.bucket.acquire()
        fd, tmp = tempfile.mkstemp(suffix=".vsix")
        os.close(fd)
        limit_bytes = self.max_download_kb * 1024
        try:
            async with self.client.stream(
                    "GET", download, timeout=120.0, follow_redirects=True,
                    headers={"User-Agent": "deepseek-scanner"}) as resp:
                if resp.status_code != 200:
                    return
                total = 0
                with open(tmp, "wb") as fh:
                    async for chunk in resp.aiter_bytes():
                        total += len(chunk)
                        if total > limit_bytes:
                            log.warning("openvsx extension too large, aborting: %s.%s",
                                        ns, name)
                            return
                        fh.write(chunk)
            matches = await asyncio.to_thread(scan_archive, tmp, self.pattern,
                                              self.deny)
        except httpx.HTTPError:
            return
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

        self.store.mark_file_seen("openvsx", f"{ns}/{name}", version)
        for path, key in matches:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            if not self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=f"openvsx:{ns}.{name}",
                file_path=path,
                commit_url=f"https://open-vsx.org/extension/{ns}/{name}",
                author_name=None,
                author_email=None,
                source="openvsx",
            ):
                continue
            log.info("candidate from openvsx: %s.%s %s", ns, name, path)
            if self.stats:
                self.stats.candidates += 1
            self.candidates.put_nowait({
                "key_hash": key_hash,
                "key": key,
                "repo": f"openvsx:{ns}.{name}",
                "file_path": path,
                "commit_url": f"https://open-vsx.org/extension/{ns}/{name}",
                "author_name": None,
                "author_email": None,
                "source": "openvsx",
                "priority": "cold",
            })
