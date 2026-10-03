import asyncio
import hashlib
import logging
import re

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.stackexchange")

SEARCH_URL = "https://api.stackexchange.com/2.3/search/excerpts"


class StackExchangeEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, queries: list[str] | None = None,
                 sites: list[str] | None = None, pagesize: int = 100,
                 interval_seconds: int = 21600, api_key: str = "", stats=None,
                 deny: frozenset[str] = frozenset()):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.queries = queries or ["DEEPSEEK_API_KEY", "api.deepseek.com",
                                   "deepseek api key", "deepseek_apikey"]
        self.sites = sites or ["stackoverflow"]
        self.pagesize = min(pagesize, 100)
        self.interval_seconds = interval_seconds
        self.api_key = api_key
        self.stats = stats
        self.deny = deny
        self.bucket = TokenBucket(rate=6 / 60.0, capacity=3)

    async def run(self):
        while True:
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("stackexchange sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        for site in self.sites:
            for query in self.queries:
                if self.stats:
                    mark_beat(self.stats, "stackexchange", self.interval_seconds)
                await self.bucket.acquire()
                params = {"order": "desc", "sort": "activity", "q": query,
                          "site": site, "pagesize": self.pagesize,
                          "filter": "withbody"}
                if self.api_key:
                    params["key"] = self.api_key
                try:
                    resp = await self.client.get(SEARCH_URL, params=params,
                                                 timeout=30.0)
                except httpx.HTTPError as exc:
                    log.warning("stackexchange request failed: %s", exc)
                    return
                if resp.status_code == 400:
                    log.warning("stackexchange bad request for %r", query)
                    continue
                if resp.status_code == 429:
                    log.warning("stackexchange throttled, skipping sweep")
                    return
                if resp.status_code != 200:
                    log.warning("stackexchange HTTP %d", resp.status_code)
                    return
                try:
                    data = resp.json()
                except ValueError:
                    return
                items = data.get("items") or []
                if self.stats:
                    self.stats.stack_hits += len(items)
                log.info("stackexchange %s %r: %d items (quota %s)",
                         site, query, len(items), data.get("quota_remaining"))
                for item in items:
                    self._process_item(site, query, item)
                backoff = data.get("backoff")
                if backoff:
                    await asyncio.sleep(backoff)

    def _process_item(self, site: str, query: str, item: dict):
        text = (item.get("body") or "") + "\n" + (item.get("title") or "")
        for key in extract_keys(text, self.pattern):
            if is_placeholder(key, self.deny):
                continue
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            link = item.get("link")
            owner = (item.get("owner") or {}).get("display_name")
            if not self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=f"{site} post",
                file_path=item.get("title"),
                commit_url=link,
                author_name=owner,
                author_email=None,
                source="stackexchange",
            ):
                continue
            log.info("candidate from stackexchange: %s", link)
            if self.stats:
                self.stats.candidates += 1
            self.candidates.put_nowait({
                "key_hash": key_hash,
                "key": key,
                "repo": f"{site} post",
                "file_path": item.get("title"),
                "commit_url": link,
                "author_name": owner,
                "author_email": None,
                "source": "stackexchange",
                "priority": "cold",
            })
