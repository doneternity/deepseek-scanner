import asyncio
import logging
import re
from collections import OrderedDict

import httpx

from scanner.diffscan import DiffScanner
from scanner.ratelimit import TokenBucket
from scanner.tokens import TokenPool
from scanner.ui import mark_beat

log = logging.getLogger("scanner.events")

EVENTS_URL = "https://api.github.com/events?per_page=100"


class EventsEngine:
    def __init__(self, *, client: httpx.AsyncClient, tokens: TokenPool,
                 pattern: re.Pattern, store, candidates: asyncio.Queue,
                 poll_interval: int = 30, max_shas: int = 100000,
                 patch_bucket: TokenBucket | None = None, stats=None,
                 deny: frozenset[str] = frozenset(), hot: bool = True,
                 pages: int = 3):
        self.client = client
        self.tokens = tokens
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.poll_interval = poll_interval
        self.max_shas = max_shas
        self.stats = stats
        self.deny = deny
        self.pages = max(1, pages)
        self.processed = OrderedDict()
        for sha in store.load_processed_shas():
            self.processed[sha] = True
        self.scanner = DiffScanner(
            client=client,
            pattern=pattern,
            store=store,
            candidates=candidates,
            patch_bucket=patch_bucket or TokenBucket(rate=2.0, capacity=120),
            stats=stats,
            deny=deny,
            source="events",
            hot=hot,
        )

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
                log.exception("events poll failed")
            await asyncio.sleep(self.poll_interval)

    async def poll_once(self):
        await self._poll()

    async def _poll(self):
        all_events = []
        for page in range(1, self.pages + 1):
            headers = await self._api_headers()
            etag_key = "events_etag" if page == 1 else f"events_etag_p{page}"
            etag = self.store.kv_get(etag_key)
            if etag:
                headers["If-None-Match"] = etag
            try:
                resp = await self.client.get(
                    EVENTS_URL, params={"per_page": 100, "page": page},
                    headers=headers, timeout=30.0)
            except httpx.HTTPError as exc:
                log.warning("events request failed: %s", exc)
                break

            if self.stats:
                mark_beat(self.stats, "events", self.poll_interval)
            if resp.status_code == 304:
                if page == 1:
                    return
                continue
            if resp.status_code != 200:
                log.warning("events HTTP %d", resp.status_code)
                break

            if page == 1 and self.stats:
                remain = resp.headers.get("X-RateLimit-Remaining", "?")
                limit = resp.headers.get("X-RateLimit-Limit", "?")
                self.stats.core_rate = f"{remain}/{limit}"

            if page == 1:
                interval = resp.headers.get("X-Poll-Interval")
                if interval:
                    try:
                        self.poll_interval = max(10, min(300, int(interval)))
                    except ValueError:
                        pass

            new_etag = resp.headers.get("ETag")
            if new_etag:
                self.store.kv_set(etag_key, new_etag)

            try:
                page_events = resp.json()
            except ValueError:
                log.warning("events returned non-JSON")
                break
            if not isinstance(page_events, list) or not page_events:
                break
            all_events.extend(page_events)
            if len(page_events) < 100:
                break

        if not all_events:
            return

        new_pushes = []
        for event in all_events:
            if event.get("type") != "PushEvent":
                continue
            repo = event.get("repo") or {}
            repo_name = repo.get("name")
            payload = event.get("payload") or {}
            head = payload.get("head")
            if not repo_name or not head:
                continue
            if head in self.processed:
                continue
            new_pushes.append((repo_name, payload.get("before"), head))

        if self.stats:
            self.stats.events_seen += len(all_events)
            self.stats.events_new += len(new_pushes)
        log.info("events: %d total across %d pages, %d new push commits",
                 len(all_events), min(self.pages, max(1, len(all_events) // 100 + 1)),
                 len(new_pushes))
        results = await asyncio.gather(
            *[self.scanner.scan_push(repo, before, head)
              for repo, before, head in new_pushes],
            return_exceptions=True,
        )
        for (_, _, head), res in zip(new_pushes, results):
            if res is True:
                self._mark_processed(head)

    def _mark_processed(self, sha: str):
        if sha in self.processed:
            self.processed.move_to_end(sha)
        else:
            self.processed[sha] = True
            while len(self.processed) > self.max_shas:
                self.processed.popitem(last=False)
