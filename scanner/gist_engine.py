import asyncio
import hashlib
import logging
import re

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.tokens import TokenPool
from scanner.ui import mark_beat

log = logging.getLogger("scanner.gists")

GISTS_URL = "https://api.github.com/gists/public"


class GistEngine:
    def __init__(self, *, client: httpx.AsyncClient, tokens: TokenPool,
                 pattern: re.Pattern, store, candidates: asyncio.Queue,
                 poll_interval: int = 60, pages: int = 2, stats=None,
                 deny: frozenset[str] = frozenset(),
                 raw_concurrency: int = 10):
        self.client = client
        self.tokens = tokens
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.poll_interval = poll_interval
        self.pages = max(1, pages)
        self.stats = stats
        self.deny = deny
        self.raw_sem = asyncio.Semaphore(raw_concurrency)
        self.last_etag = store.kv_get("gists_etag")

    async def _api_headers(self):
        token = await self.tokens.acquire()
        headers = {"User-Agent": "deepseek-scanner"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def run(self):
        while True:
            try:
                await self._poll()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("gists poll failed")
            await asyncio.sleep(self.poll_interval)

    async def poll_once(self):
        await self._poll()

    async def _poll(self):
        gists = []
        headers = await self._api_headers()
        if self.last_etag:
            headers["If-None-Match"] = self.last_etag
        params = {"per_page": 100, "page": 1}
        try:
            resp = await self.client.get(GISTS_URL, params=params,
                                         headers=headers, timeout=30.0)
        except httpx.HTTPError as exc:
            log.warning("gists request failed: %s", exc)
            return

        if self.stats:
            mark_beat(self.stats, "gists", self.poll_interval)
        if resp.status_code == 304:
            return
        if resp.status_code != 200:
            log.warning("gists HTTP %d", resp.status_code)
            return

        etag = resp.headers.get("ETag")
        if etag:
            self.last_etag = etag
            self.store.kv_set("gists_etag", etag)

        try:
            page_gists = resp.json()
        except ValueError:
            log.warning("gists returned non-JSON")
            return
        if not isinstance(page_gists, list):
            return
        gists.extend(page_gists)

        if len(page_gists) >= 100 and self.pages > 1:
            results = await asyncio.gather(
                *[self._fetch_page(page) for page in range(2, self.pages + 1)],
                return_exceptions=True,
            )
            for res in results:
                if isinstance(res, list):
                    gists.extend(res)

        new_gists = []
        for gist in gists:
            gist_id = gist.get("id")
            updated_at = gist.get("updated_at")
            if not gist_id or self.store.gist_seen(gist_id, updated_at):
                continue
            new_gists.append(gist)

        if self.stats:
            self.stats.gists_seen += len(gists)
            self.stats.gists_new += len(new_gists)
        log.info("gists: %d total, %d new", len(gists), len(new_gists))
        await asyncio.gather(
            *[self._scan_gist(gist) for gist in new_gists],
            return_exceptions=True,
        )

    async def _fetch_page(self, page: int):
        headers = await self._api_headers()
        params = {"per_page": 100, "page": page}
        try:
            resp = await self.client.get(GISTS_URL, params=params,
                                         headers=headers, timeout=30.0)
        except httpx.HTTPError:
            return None
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        return data if isinstance(data, list) else None

    async def _scan_gist(self, gist: dict):
        gist_id = gist.get("id")
        updated_at = gist.get("updated_at")
        html_url = gist.get("html_url")
        owner = gist.get("owner") or {}
        owner_login = owner.get("login")
        files = gist.get("files") or {}

        for name, meta in files.items():
            raw_url = meta.get("raw_url") if isinstance(meta, dict) else None
            if not raw_url:
                continue
            async with self.raw_sem:
                try:
                    resp = await self.client.get(raw_url, timeout=30.0,
                                                 follow_redirects=True)
                except httpx.HTTPError as exc:
                    log.debug("gist raw fetch failed %s: %s", raw_url, exc)
                    continue
                if resp.status_code != 200:
                    log.debug("gist raw HTTP %d for %s", resp.status_code, raw_url)
                    continue

                for key in extract_keys(resp.text, self.pattern):
                    if is_placeholder(key, self.deny):
                        continue
                    key_hash = hashlib.sha256(key.encode()).hexdigest()
                    if self.store.add_candidate(
                        key_hash=key_hash,
                        key=key,
                        repo=owner_login or f"gist:{gist_id}",
                        file_path=name,
                        commit_url=html_url,
                        author_name=owner_login,
                        author_email=None,
                        source="gists",
                    ):
                        log.info("candidate from gist: %s %s", owner_login, name)
                        if self.stats:
                            self.stats.candidates += 1
                        await self.candidates.put({
                            "key_hash": key_hash,
                            "key": key,
                            "repo": owner_login or f"gist:{gist_id}",
                            "file_path": name,
                            "commit_url": html_url,
                            "author_name": owner_login,
                            "author_email": None,
                            "source": "gists",
                        })

        if gist_id:
            self.store.mark_gist_seen(gist_id, updated_at)
