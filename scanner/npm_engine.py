import asyncio
import hashlib
import logging
import os
import re
import tempfile
import urllib.parse
from collections import OrderedDict

import httpx

from scanner.pkgscan import scan_archive
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.npm")

CHANGES_URL = "https://replicate.npmjs.com/_changes"
REGISTRY_URL = "https://registry.npmjs.org/{pkg}"


class NpmEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, stats=None, deny: frozenset[str] = frozenset(),
                 poll_interval: int = 60, limit: int = 200,
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
        self.limit = limit
        self.scan_terms = [t.lower() for t in (scan_terms or ["deepseek"])]
        self.max_size_kb = max_size_kb
        self.max_size_kb_term = max_size_kb_term
        self.max_download_kb = max_download_kb
        self.bucket = TokenBucket(rate=3.0, capacity=60)
        self.registry_bucket = TokenBucket(rate=6.0, capacity=40)
        self._recent: OrderedDict = OrderedDict()

    async def run(self):
        while True:
            try:
                await self.poll()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("npm poll failed")
            await asyncio.sleep(self.poll_interval)

    async def poll(self):
        seq = self.store.kv_get("npm_last_seq")
        if seq is None:
            try:
                resp = await self.client.get(CHANGES_URL,
                                             params={"since": "0", "limit": 1},
                                             timeout=30.0)
                if resp.status_code != 200:
                    log.warning("npm changes HTTP %d", resp.status_code)
                    return
                last_seq = resp.json().get("last_seq")
                if last_seq is not None:
                    self.store.kv_set("npm_last_seq", str(last_seq))
                    log.info("npm: cursor synced to seq %s", last_seq)
            except httpx.HTTPError as exc:
                log.warning("npm cursor sync failed: %s", exc)
            return

        try:
            since = str(max(0, int(seq) - 200))
        except (TypeError, ValueError):
            since = seq
        params = {"since": since, "limit": self.limit}
        try:
            resp = await self.client.get(CHANGES_URL, params=params, timeout=30.0)
        except httpx.HTTPError as exc:
            log.warning("npm changes request failed: %s", exc)
            return
        if self.stats:
            mark_beat(self.stats, "npm", self.poll_interval)
        if resp.status_code != 200:
            log.warning("npm changes HTTP %d", resp.status_code)
            return
        data = resp.json()
        last_seq = data.get("last_seq")
        if last_seq is not None:
            self.store.kv_set("npm_last_seq", str(last_seq))

        entries = []
        for item in data.get("results", []):
            pkg = item.get("id")
            if not pkg or item.get("deleted"):
                continue
            rev = ((item.get("changes") or [{}])[0] or {}).get("rev", "")
            entries.append((pkg, rev))
        if self.stats:
            self.stats.npm_pkgs += len(entries)
        log.info("npm: %d new package revisions", len(entries))
        await asyncio.gather(*[self._process_pkg(pkg, rev) for pkg, rev in entries],
                             return_exceptions=True)

    async def _process_pkg(self, pkg: str, rev: str = ""):
        if rev:
            key = (pkg, rev)
            if key in self._recent:
                return
            self._recent[key] = None
            while len(self._recent) > 5000:
                self._recent.popitem(last=False)
        await self.registry_bucket.acquire()
        url = REGISTRY_URL.format(pkg=urllib.parse.quote(pkg, safe="@"))
        try:
            resp = await self.client.get(
                url, headers={"Accept": "application/vnd.npm.install-v1+json"},
                timeout=30.0,
            )
        except httpx.HTTPError:
            return
        if resp.status_code != 200:
            return
        try:
            doc = resp.json()
        except ValueError:
            return
        latest = (doc.get("dist-tags") or {}).get("latest")
        if not latest:
            return
        ver = (doc.get("versions") or {}).get(latest) or {}
        dist = ver.get("dist") or {}
        tarball = dist.get("tarball")
        unpacked = int(dist.get("unpackedSize") or 0)
        if not tarball:
            return

        name_lower = (pkg + " " + (doc.get("description") or "")).lower()
        term_match = any(t in name_lower for t in self.scan_terms)
        cap = self.max_size_kb_term if term_match else self.max_size_kb
        if unpacked and unpacked > cap * 1024:
            return

        await self.bucket.acquire()
        fd, tmp = tempfile.mkstemp(suffix=".tgz")
        os.close(fd)
        limit_bytes = self.max_download_kb * 1024
        try:
            async with self.client.stream("GET", tarball, timeout=60.0,
                                          follow_redirects=True) as resp:
                if resp.status_code != 200:
                    return
                total = 0
                with open(tmp, "wb") as fh:
                    async for chunk in resp.aiter_bytes():
                        total += len(chunk)
                        if total > limit_bytes:
                            log.warning("npm tarball too large, aborting: %s", pkg)
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
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            if not self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=pkg,
                file_path=path,
                commit_url=f"https://www.npmjs.com/package/{urllib.parse.quote(pkg, safe='@')}",
                author_name=None,
                author_email=None,
                source="npm",
            ):
                continue
            log.info("candidate from npm: %s %s", pkg, path)
            if self.stats:
                self.stats.candidates += 1
            await self.candidates.put({
                "key_hash": key_hash,
                "key": key,
                "repo": pkg,
                "file_path": path,
                "commit_url": f"https://www.npmjs.com/package/{urllib.parse.quote(pkg, safe='@')}",
                "author_name": None,
                "author_email": None,
                "source": "npm",
                "priority": "hot",
            })
