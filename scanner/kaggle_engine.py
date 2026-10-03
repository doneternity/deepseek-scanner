import asyncio
import base64
import hashlib
import logging
import os
import re
import tempfile

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.pkgscan import scan_archive
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.kaggle")

LIST_URL = "https://www.kaggle.com/api/v1/datasets/list"
DOWNLOAD_URL = "https://www.kaggle.com/api/v1/datasets/download/{ref}"
KERNELS_URL = "https://www.kaggle.com/api/v1/kernels/list"
KERNEL_PULL_URL = "https://www.kaggle.com/api/v1/kernels/pull/{ref}"


class KaggleEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, queries: list[str] | None = None,
                 max_datasets: int = 30, max_download_kb: int = 25000,
                 interval_seconds: int = 43200, stats=None,
                 deny: frozenset[str] = frozenset(),
                 username: str = "", key: str = "",
                 notebooks: bool = True, max_notebooks: int = 30):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.queries = queries or ["deepseek", "deepseek api", "deepseek key"]
        self.max_datasets = max_datasets
        self.max_download_kb = max_download_kb
        self.interval_seconds = interval_seconds
        self.stats = stats
        self.deny = deny
        self.username = username
        self.key = key
        self.notebooks = notebooks and bool(username and key)
        self.max_notebooks = max_notebooks
        self.bucket = TokenBucket(rate=0.5, capacity=5)
        if notebooks and not self.notebooks:
            log.info("kaggle notebooks disabled (no username/key configured)")

    def _auth_headers(self) -> dict:
        token = base64.b64encode(
            f"{self.username}:{self.key}".encode()).decode()
        return {"User-Agent": "deepseek-scanner",
                "Authorization": f"Basic {token}"}

    async def run(self):
        while True:
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("kaggle sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        refs: list[tuple[str, int]] = []
        seen: set[str] = set()
        for query in self.queries:
            for page in (1, 2):
                if self.stats:
                    mark_beat(self.stats, "kaggle", self.interval_seconds)
                await self.bucket.acquire()
                try:
                    resp = await self.client.get(
                        LIST_URL, params={"search": query, "page": page},
                        headers={"User-Agent": "deepseek-scanner"}, timeout=30.0)
                except httpx.HTTPError as exc:
                    log.warning("kaggle list failed: %s", exc)
                    break
                if resp.status_code != 200:
                    log.warning("kaggle list HTTP %d", resp.status_code)
                    break
                try:
                    items = resp.json()
                except ValueError:
                    break
                if not isinstance(items, list) or not items:
                    break
                for item in items:
                    ref = item.get("refNullable") or item.get("ref") or ""
                    size = int(item.get("totalBytesNullable")
                               or item.get("totalBytes") or 0)
                    if ref and ref not in seen:
                        seen.add(ref)
                        refs.append((ref, size))
                if len(items) < 20:
                    break
        if self.stats:
            self.stats.kaggle_sets += len(refs)
        log.info("kaggle: %d datasets to inspect", len(refs))

        checked = 0
        for ref, size in refs:
            if checked >= self.max_datasets:
                break
            if size and size > self.max_download_kb * 1024:
                continue
            if self.store.file_seen("kaggle", ref, str(size)):
                continue
            checked += 1
            try:
                await self._scan_dataset(ref, size)
            except Exception:
                log.exception("kaggle dataset scan failed: %s", ref)

        if self.notebooks:
            try:
                await self._scan_notebooks()
            except Exception:
                log.exception("kaggle notebook sweep failed")

    async def _scan_notebooks(self):
        count = 0
        seen: set[str] = set()
        for query in self.queries:
            await self.bucket.acquire()
            try:
                resp = await self.client.get(
                    KERNELS_URL,
                    params={"search": query, "page": 1, "pageSize": 20},
                    headers=self._auth_headers(), timeout=30.0)
            except httpx.HTTPError as exc:
                log.warning("kaggle kernels list failed: %s", exc)
                continue
            if resp.status_code in (401, 403):
                log.warning("kaggle notebook credentials rejected, disabling notebooks")
                self.notebooks = False
                return
            if resp.status_code != 200:
                continue
            try:
                items = resp.json()
            except ValueError:
                continue
            if not isinstance(items, list):
                continue
            for item in items:
                if count >= self.max_notebooks:
                    break
                ref = item.get("ref") or ""
                version = str(item.get("versionNumber")
                              or item.get("lastRunTime") or "")
                if not ref or ref in seen:
                    continue
                seen.add(ref)
                if self.store.file_seen("kaggle-nb", ref, version):
                    continue
                count += 1
                try:
                    await self._scan_notebook(ref, version)
                except Exception:
                    log.exception("kaggle notebook scan failed: %s", ref)
            if count >= self.max_notebooks:
                break
        if self.stats:
            self.stats.kaggle_nbs += count
        log.info("kaggle notebooks: scanned %d", count)

    async def _scan_notebook(self, ref: str, version: str):
        await self.bucket.acquire()
        try:
            resp = await self.client.get(KERNEL_PULL_URL.format(ref=ref),
                                         headers=self._auth_headers(), timeout=30.0)
        except httpx.HTTPError:
            return
        if resp.status_code != 200:
            return
        try:
            data = resp.json()
        except ValueError:
            return
        source = (data.get("blob") or {}).get("source") or ""
        if not source:
            return
        self.store.mark_file_seen("kaggle-nb", ref, version)
        for key in extract_keys(source, self.pattern):
            if is_placeholder(key, self.deny):
                continue
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            if not self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=f"kaggle:{ref}",
                file_path="notebook source",
                commit_url=f"https://www.kaggle.com/code/{ref}",
                author_name=None,
                author_email=None,
                source="kaggle",
            ):
                continue
            log.info("candidate from kaggle notebook: %s", ref)
            if self.stats:
                self.stats.candidates += 1
            self.candidates.put_nowait({
                "key_hash": key_hash,
                "key": key,
                "repo": f"kaggle:{ref}",
                "file_path": "notebook source",
                "commit_url": f"https://www.kaggle.com/code/{ref}",
                "author_name": None,
                "author_email": None,
                "source": "kaggle",
                "priority": "cold",
            })

    async def _scan_dataset(self, ref: str, size: int):
        await self.bucket.acquire()
        fd, tmp = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        limit_bytes = self.max_download_kb * 1024
        try:
            async with self.client.stream(
                    "GET", DOWNLOAD_URL.format(ref=ref), timeout=120.0,
                    follow_redirects=True,
                    headers={"User-Agent": "deepseek-scanner"}) as resp:
                if resp.status_code != 200:
                    return
                total = 0
                with open(tmp, "wb") as fh:
                    async for chunk in resp.aiter_bytes():
                        total += len(chunk)
                        if total > limit_bytes:
                            log.warning("kaggle dataset too large, aborting: %s", ref)
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

        self.store.mark_file_seen("kaggle", ref, str(size))
        for path, key in matches:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            if not self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=f"kaggle:{ref}",
                file_path=path,
                commit_url=f"https://www.kaggle.com/datasets/{ref}",
                author_name=None,
                author_email=None,
                source="kaggle",
            ):
                continue
            log.info("candidate from kaggle: %s %s", ref, path)
            if self.stats:
                self.stats.candidates += 1
            self.candidates.put_nowait({
                "key_hash": key_hash,
                "key": key,
                "repo": f"kaggle:{ref}",
                "file_path": path,
                "commit_url": f"https://www.kaggle.com/datasets/{ref}",
                "author_name": None,
                "author_email": None,
                "source": "kaggle",
                "priority": "cold",
            })
