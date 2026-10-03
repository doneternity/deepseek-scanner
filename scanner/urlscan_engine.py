import asyncio
import hashlib
import logging
import re

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.urlscan")

SEARCH_URL = "https://urlscan.io/api/v1/search/"
RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"
RESPONSE_URL = "https://urlscan.io/responses/{hash}/"
ENV_FILENAMES = (".env", ".env.local", ".env.production", ".env.development")


class UrlscanEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, stats=None, deny: frozenset[str] = frozenset(),
                 api_key: str = "", interval_seconds: int = 21600):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.stats = stats
        self.deny = deny
        self.api_key = api_key
        self.interval_seconds = interval_seconds
        self.bucket = TokenBucket(rate=20 / 60.0, capacity=10)

    def _headers(self):
        headers = {"User-Agent": "deepseek-scanner"}
        if self.api_key:
            headers["API-Key"] = self.api_key
        return headers

    async def run(self):
        while True:
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("urlscan sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        for fname in ENV_FILENAMES:
            if self.stats:
                mark_beat(self.stats, "urlscan", self.interval_seconds)
            await self.bucket.acquire()
            try:
                resp = await self.client.get(
                    SEARCH_URL, params={"q": f"filename:{fname}", "size": 100},
                    headers=self._headers(), timeout=30.0,
                )
            except httpx.HTTPError as exc:
                log.warning("urlscan search failed: %s", exc)
                return
            if resp.status_code == 429:
                log.warning("urlscan rate limited, skipping sweep")
                return
            if resp.status_code != 200:
                log.warning("urlscan HTTP %d", resp.status_code)
                return
            try:
                results = resp.json().get("results", [])
            except ValueError:
                log.warning("urlscan returned non-JSON")
                return
            log.info("urlscan %s: %d scans", fname, len(results))
            if self.stats:
                self.stats.urlscan_hits += len(results)
            await asyncio.gather(
                *[self._process_scan(r, fname) for r in results],
                return_exceptions=True,
            )

    async def _process_scan(self, result: dict, fname: str):
        uuid = result.get("_id") or result.get("uuid")
        if not uuid:
            return
        await self.bucket.acquire()
        try:
            resp = await self.client.get(RESULT_URL.format(uuid=uuid),
                                         headers=self._headers(), timeout=30.0)
        except httpx.HTTPError:
            return
        if resp.status_code != 200:
            return

        try:
            data = resp.json()
        except ValueError:
            return
        host = ((data.get("task") or {}).get("url") or "").replace("https://", "").replace("http://", "").split("/")[0]
        for req in data.get("data", {}).get("requests", []):
            url = (req.get("request") or {}).get("url") or ""
            if not url.endswith(fname):
                continue
            response = req.get("response") or {}
            digest = response.get("hash")
            if not digest or response.get("size", 0) > 1_000_000:
                continue
            await self.bucket.acquire()
            try:
                body = await self.client.get(RESPONSE_URL.format(hash=digest),
                                             headers=self._headers(), timeout=30.0)
            except httpx.HTTPError:
                continue
            if body.status_code != 200:
                continue
            for key in extract_keys(body.text, self.pattern):
                if is_placeholder(key, self.deny):
                    continue
                key_hash = hashlib.sha256(key.encode()).hexdigest()
                if self.store.add_candidate(
                    key_hash=key_hash,
                    key=key,
                    repo=host or f"urlscan:{uuid}",
                    file_path=url.split("/")[-1],
                    commit_url=f"https://urlscan.io/result/{uuid}/",
                    author_name=None,
                    author_email=None,
                    source="urlscan",
                ):
                    log.info("candidate from urlscan: %s", host)
                    if self.stats:
                        self.stats.candidates += 1
                    await self.candidates.put({
                        "key_hash": key_hash,
                        "key": key,
                        "repo": host or f"urlscan:{uuid}",
                        "file_path": url.split("/")[-1],
                        "commit_url": f"https://urlscan.io/result/{uuid}/",
                        "author_name": None,
                        "author_email": None,
                        "source": "urlscan",
                        "priority": "cold",
                    })
