import asyncio
import hashlib
import logging
import re

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.grep")

GREPAPP_URL = "https://grep.app/api/search"
RAW_URL = "https://raw.githubusercontent.com/{repo}/{branch}/{path}"


class GrepEngine:
    def __init__(self, *, client: httpx.AsyncClient, queries: list[tuple[str, bool]],
                 pattern: re.Pattern, store, candidates: asyncio.Queue,
                 interval_seconds: int = 7200, requests_per_minute: int = 6,
                 stats=None, deny: frozenset[str] = frozenset()):
        self.client = client
        self.queries = queries
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.interval_seconds = interval_seconds
        self.bucket = TokenBucket(rate=requests_per_minute / 60.0, capacity=1)
        self.stats = stats
        self.deny = deny

    async def run(self):
        while True:
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("grep sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        for query, regexp in self.queries:
            if self.stats:
                mark_beat(self.stats, "grepapp", self.interval_seconds)
            await self.bucket.acquire()
            params = {"q": query}
            if regexp:
                params["regexp"] = "true"
            headers = {"User-Agent": "deepseek-scanner", "Accept": "application/json"}
            try:
                resp = await self.client.get(GREPAPP_URL, params=params,
                                             headers=headers, timeout=30.0,
                                             follow_redirects=True)
            except httpx.HTTPError as exc:
                log.warning("grep.app request failed: %s", exc)
                continue

            if resp.status_code == 429:
                log.warning("grep.app rate limited or bot-blocked, skipping this sweep")
                return
            if resp.status_code != 200:
                log.warning("grep.app HTTP %d for %r", resp.status_code, query)
                continue

            try:
                data = resp.json()
            except ValueError:
                log.warning("grep.app returned non-JSON for %r", query)
                continue

            hits = (data.get("hits") or {}).get("hits") or []
            log.info("grep.app query=%r hits=%d total=%d", query, len(hits),
                     (data.get("hits") or {}).get("total", 0))
            if self.stats:
                self.stats.grep_hits += len(hits)

            await asyncio.gather(
                *[self._process_hit(hit) for hit in hits],
                return_exceptions=True,
            )

    async def _process_hit(self, hit: dict):
        repo_obj = hit.get("repo") or {}
        path_obj = hit.get("path") or {}
        content_obj = hit.get("content") or {}
        repo = repo_obj.get("raw")
        branch = repo_obj.get("branch")
        path = path_obj.get("raw")
        snippet = content_obj.get("snippet") or ""
        if not repo or not path:
            return

        text = snippet
        if not snippet or not self.pattern.search(snippet):
            if not branch:
                return
            url = RAW_URL.format(repo=repo, branch=branch, path=path)
            try:
                resp = await self.client.get(url, timeout=30.0, follow_redirects=True)
            except httpx.HTTPError:
                return
            if resp.status_code != 200:
                return
            text = resp.text

        for key in extract_keys(text, self.pattern):
            if is_placeholder(key, self.deny):
                continue
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            commit_url = None
            if branch:
                commit_url = f"https://github.com/{repo}/blob/{branch}/{path}"
            if self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=repo,
                file_path=path,
                commit_url=commit_url,
                author_name=None,
                author_email=None,
                source="grepapp",
            ):
                log.info("candidate from grep.app: %s %s", repo, path)
                if self.stats:
                    self.stats.candidates += 1
                await self.candidates.put({
                    "key_hash": key_hash,
                    "key": key,
                    "repo": repo,
                    "file_path": path,
                    "commit_url": commit_url,
                    "author_name": None,
                    "author_email": None,
                    "source": "grepapp",
                })
