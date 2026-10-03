import asyncio
import hashlib
import logging
import re
import urllib.parse

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.gitlab")


class GitlabEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, stats=None, deny: frozenset[str] = frozenset(),
                 token: str = "", host: str = "https://gitlab.com",
                 interval_seconds: int = 7200,
                 queries: list[str] | None = None, max_pages: int = 20):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.stats = stats
        self.deny = deny
        self.token = token
        self.host = host.rstrip("/")
        self.interval_seconds = interval_seconds
        self.queries = queries or ["DEEPSEEK_API_KEY", "api.deepseek.com"]
        self.max_pages = max_pages
        self.bucket = TokenBucket(rate=1.0, capacity=10)

    def _headers(self):
        headers = {"User-Agent": "deepseek-scanner"}
        if self.token:
            headers["PRIVATE-TOKEN"] = self.token
        return headers

    async def run(self):
        while True:
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("gitlab sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        for term in self.queries:
            for page in range(1, self.max_pages + 1):
                if self.stats:
                    mark_beat(self.stats, "gitlab", self.interval_seconds)
                await self.bucket.acquire()
                params = {"scope": "blobs", "search": term,
                          "per_page": 100, "page": page}
                try:
                    resp = await self.client.get(
                        f"{self.host}/api/v4/search", params=params,
                        headers=self._headers(), timeout=30.0,
                    )
                except httpx.HTTPError as exc:
                    log.warning("gitlab search failed: %s", exc)
                    return
                if resp.status_code == 401:
                    log.warning("gitlab token rejected, disabling sweep")
                    return
                if resp.status_code == 429:
                    log.warning("gitlab rate limited, backing off")
                    await asyncio.sleep(60)
                    continue
                if resp.status_code != 200:
                    log.warning("gitlab HTTP %d for %r", resp.status_code, term)
                    return

                items = resp.json()
                if not isinstance(items, list):
                    return
                log.info("gitlab %r page %d: %d blobs", term, page, len(items))
                if self.stats:
                    self.stats.gitlab_hits += len(items)
                await asyncio.gather(
                    *[self._process_blob(b) for b in items],
                    return_exceptions=True,
                )
                if len(items) < 100:
                    break

    async def _process_blob(self, blob: dict):
        project_id = blob.get("project_id")
        path = blob.get("path")
        ref = blob.get("ref") or "master"
        if not project_id or not path:
            return
        encoded = urllib.parse.quote(path, safe="")
        url = (f"{self.host}/api/v4/projects/{project_id}/repository/files/"
               f"{encoded}/raw?ref={urllib.parse.quote(ref, safe='')}")
        await self.bucket.acquire()
        try:
            resp = await self.client.get(url, headers=self._headers(), timeout=30.0)
        except httpx.HTTPError:
            return
        if resp.status_code != 200:
            return

        repo = str(blob.get("project_id"))
        commit_url = None
        matches: list[tuple[str, str]] = []
        for key in extract_keys(resp.text, self.pattern):
            if is_placeholder(key, self.deny):
                continue
            matches.append((path, key))

        if not matches:
            return

        await self.bucket.acquire()
        try:
            proj = await self.client.get(
                f"{self.host}/api/v4/projects/{project_id}",
                headers=self._headers(), timeout=30.0)
            if proj.status_code == 200:
                data = proj.json()
                repo = data.get("path_with_namespace") or repo
                commit_url = data.get("web_url")
        except httpx.HTTPError:
            pass

        for fpath, key in matches:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            if self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=repo,
                file_path=fpath,
                commit_url=commit_url,
                author_name=None,
                author_email=None,
                source="gitlab",
            ):
                log.info("candidate from gitlab: project %s %s", repo, fpath)
                if self.stats:
                    self.stats.candidates += 1
                await self.candidates.put({
                    "key_hash": key_hash,
                    "key": key,
                    "repo": repo,
                    "file_path": fpath,
                    "commit_url": commit_url,
                    "author_name": None,
                    "author_email": None,
                    "source": "gitlab",
                    "priority": "cold",
                })
