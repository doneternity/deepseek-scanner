import asyncio
import hashlib
import logging
import re

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.hf")

SEARCH_URL = "https://huggingface.co/api/search/full-text"
RAW_URLS = {
    "space": "https://huggingface.co/spaces/{name}/raw/main/{path}",
    "dataset": "https://huggingface.co/datasets/{name}/raw/main/{path}",
    "model": "https://huggingface.co/{name}/raw/main/{path}",
}
PREFIXES = {
    "space": "spaces/{name}",
    "dataset": "datasets/{name}",
    "model": "{name}",
}


class HFEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, queries: list[str] | None = None, limit: int = 100,
                 max_pages: int = 3, interval_seconds: int = 3600, stats=None,
                 deny: frozenset[str] = frozenset(), hot: bool = True,
                 token: str = ""):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.queries = queries or ["api.deepseek.com", "DEEPSEEK_API_KEY",
                                   "deepseek_api_key", "DEEPSEEK_BASE_URL"]
        self.limit = min(limit, 100)
        self.max_pages = max_pages
        self.interval_seconds = interval_seconds
        self.stats = stats
        self.deny = deny
        self.hot = hot
        self.token = token
        self.bucket = TokenBucket(rate=1.0, capacity=5)
        self.raw_sem = asyncio.Semaphore(5)

    def _headers(self):
        headers = {"User-Agent": "deepseek-scanner",
                   "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def run(self):
        while True:
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("hf sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        for query in self.queries:
            for page in range(self.max_pages):
                if self.stats:
                    mark_beat(self.stats, "huggingface", self.interval_seconds)
                await self.bucket.acquire()
                params = {"q": query, "limit": self.limit,
                          "skip": page * self.limit}
                try:
                    resp = await self.client.get(SEARCH_URL, params=params,
                                                 headers=self._headers(), timeout=30.0)
                except httpx.HTTPError as exc:
                    log.warning("hf search failed: %s", exc)
                    return
                if resp.status_code == 429:
                    log.warning("hf rate limited, skipping sweep")
                    return
                if resp.status_code >= 500:
                    log.warning("hf server error %d for %r, retrying in 10s",
                                resp.status_code, query)
                    await asyncio.sleep(10)
                    try:
                        resp = await self.client.get(SEARCH_URL, params=params,
                                                     headers=self._headers(),
                                                     timeout=30.0)
                    except httpx.HTTPError as exc:
                        log.warning("hf retry failed: %s", exc)
                        break
                if resp.status_code != 200:
                    log.warning("hf HTTP %d for %r, moving to next query",
                                resp.status_code, query)
                    break
                try:
                    data = resp.json()
                except ValueError:
                    return
                hits = data.get("hits") or []
                if self.stats:
                    self.stats.hf_hits += len(hits)
                log.info("hf %r skip=%d: %d hits (total %s)", query,
                         page * self.limit, len(hits),
                         data.get("estimatedTotalHits"))
                if not hits:
                    break
                await asyncio.gather(
                    *[self._process_hit(hit) for hit in hits],
                    return_exceptions=True,
                )
                if len(hits) < self.limit:
                    break

    async def _process_hit(self, hit: dict):
        name = hit.get("name")
        file_name = hit.get("fileName")
        kind = hit.get("type") or "model"
        updated_at = str(hit.get("updatedAt") or "")
        if not name:
            return

        fragment_text = ""
        formatted = hit.get("formatted") or {}
        for frag in formatted.get("fileContent") or []:
            fragment_text += frag.get("text") or ""

        if self._emit(name, file_name, kind, fragment_text):
            return

        if not file_name:
            return
        if updated_at and self.store.file_seen(f"hf:{name}", file_name, updated_at):
            return
        template = RAW_URLS.get(kind)
        if not template:
            return
        await self.bucket.acquire()
        async with self.raw_sem:
            url = template.format(name=name, path=file_name)
            try:
                resp = await self.client.get(url, timeout=30.0,
                                             follow_redirects=True)
            except httpx.HTTPError:
                return
            if resp.status_code != 200:
                return
            if updated_at:
                self.store.mark_file_seen(f"hf:{name}", file_name, updated_at)
            self._emit(name, file_name, kind, resp.text)

    def _emit(self, name: str, file_name: str | None, kind: str, text: str) -> bool:
        found = False
        for key in extract_keys(text or "", self.pattern):
            if is_placeholder(key, self.deny):
                continue
            found = True
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            prefix = PREFIXES.get(kind, "{name}").format(name=name)
            repo_label = f"hf:{prefix}"
            commit_url = None
            if file_name:
                commit_url = f"https://huggingface.co/{prefix}/blob/main/{file_name}"
            if not self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=repo_label,
                file_path=file_name,
                commit_url=commit_url,
                author_name=None,
                author_email=None,
                source="huggingface",
            ):
                continue
            log.info("candidate from huggingface: %s %s", repo_label, file_name)
            if self.stats:
                self.stats.candidates += 1
            self.candidates.put_nowait({
                "key_hash": key_hash,
                "key": key,
                "repo": repo_label,
                "file_path": file_name,
                "commit_url": commit_url,
                "author_name": None,
                "author_email": None,
                "source": "huggingface",
                "priority": "hot" if self.hot else "cold",
            })
        return found
