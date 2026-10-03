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

log = logging.getLogger("scanner.vscode")

QUERY_URL = ("https://marketplace.visualstudio.com/_apis/public/gallery/"
             "extensionquery")
DOWNLOAD_URL = ("https://marketplace.visualstudio.com/_apis/public/gallery/"
                "publishers/{publisher}/vsextensions/{name}/{version}/vspackage")
API_VERSION = "application/json;api-version=3.0-preview.1"


class VSCodeMarketplaceEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, queries: list[str] | None = None,
                 pages: int = 2, page_size: int = 100,
                 max_extensions: int = 30, max_download_kb: int = 25000,
                 interval_seconds: int = 43200, stats=None,
                 deny: frozenset[str] = frozenset()):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.queries = queries or ["deepseek", "deepseek api"]
        self.pages = max(1, pages)
        self.page_size = min(max(page_size, 1), 100)
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
                log.exception("vscode marketplace sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        extensions: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()
        for query in self.queries:
            for page in range(1, self.pages + 1):
                if self.stats:
                    mark_beat(self.stats, "vscode", self.interval_seconds)
                await self.bucket.acquire()
                body = {
                    "filters": [{
                        "criteria": [
                            {"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
                            {"filterType": 10, "value": query},
                        ],
                        "pageNumber": page,
                        "pageSize": self.page_size,
                        "sortBy": 0,
                        "sortOrder": 0,
                    }],
                    "assetTypes": [],
                    "flags": 914,
                }
                headers = {"Content-Type": "application/json",
                           "Accept": API_VERSION,
                           "User-Agent": "deepseek-scanner"}
                try:
                    resp = await self.client.post(QUERY_URL, json=body,
                                                  headers=headers, timeout=30.0)
                except httpx.HTTPError as exc:
                    log.warning("vscode marketplace search failed: %s", exc)
                    return
                if resp.status_code != 200:
                    log.warning("vscode marketplace HTTP %d", resp.status_code)
                    return
                try:
                    results = resp.json().get("results") or []
                    items = results[0].get("extensions") or [] if results else []
                except (ValueError, IndexError, AttributeError):
                    return
                if not items:
                    break
                for item in items:
                    pub = (item.get("publisher") or {}).get("publisherName")
                    name = item.get("extensionName")
                    versions = item.get("versions") or [{}]
                    version = versions[0].get("version")
                    if not (pub and name and version):
                        continue
                    key = (pub, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    extensions.append((pub, name, version))
                if len(items) < self.page_size:
                    break

        if self.stats:
            self.stats.vscode_ext += len(extensions)
        log.info("vscode marketplace: %d extensions to inspect", len(extensions))

        count = 0
        for pub, name, version in extensions:
            if count >= self.max_extensions:
                break
            if self.store.file_seen("vscode", f"{pub}.{name}", version):
                continue
            count += 1
            try:
                await self._scan_extension(pub, name, version)
            except Exception:
                log.exception("vscode extension scan failed: %s.%s", pub, name)

    async def _scan_extension(self, pub: str, name: str, version: str):
        await self.bucket.acquire()
        fd, tmp = tempfile.mkstemp(suffix=".vsix")
        os.close(fd)
        limit_bytes = self.max_download_kb * 1024
        url = DOWNLOAD_URL.format(publisher=pub, name=name, version=version)
        try:
            async with self.client.stream(
                    "GET", url, timeout=120.0, follow_redirects=True,
                    headers={"User-Agent": "deepseek-scanner"}) as resp:
                if resp.status_code != 200:
                    return
                total = 0
                with open(tmp, "wb") as fh:
                    async for chunk in resp.aiter_bytes():
                        total += len(chunk)
                        if total > limit_bytes:
                            log.warning("vscode extension too large, aborting: %s.%s",
                                        pub, name)
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

        self.store.mark_file_seen("vscode", f"{pub}.{name}", version)
        for path, key in matches:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            if not self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=f"vscode:{pub}.{name}",
                file_path=path,
                commit_url=f"https://marketplace.visualstudio.com/items?itemName={pub}.{name}",
                author_name=None,
                author_email=None,
                source="vscode",
            ):
                continue
            log.info("candidate from vscode marketplace: %s.%s %s", pub, name, path)
            if self.stats:
                self.stats.candidates += 1
            self.candidates.put_nowait({
                "key_hash": key_hash,
                "key": key,
                "repo": f"vscode:{pub}.{name}",
                "file_path": path,
                "commit_url": f"https://marketplace.visualstudio.com/items?itemName={pub}.{name}",
                "author_name": None,
                "author_email": None,
                "source": "vscode",
                "priority": "cold",
            })
