import asyncio
import hashlib
import json
import logging
import re
import time

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.tokens import TokenPool
from scanner.ui import mark_beat

log = logging.getLogger("scanner.search")

SEARCH_URL = "https://api.github.com/search/code"
RAW_URL = "https://raw.githubusercontent.com/{repo}/{branch}/{path}"


def build_query_list(search_cfg: dict) -> list[tuple[str, int]]:
    max_pages = search_cfg.get("max_pages_per_query", 10)
    queries = [(q, max_pages) for q in search_cfg.get("queries", [])]
    extensions = search_cfg.get("extensions", [])
    terms = search_cfg.get("extension_terms", [])
    ext_pages = search_cfg.get("extension_pages", 3)
    for term in terms:
        for ext in extensions:
            queries.append((f"{term} extension:{ext}", ext_pages))
    languages = search_cfg.get("languages", [])
    lang_terms = search_cfg.get("language_terms", [])
    lang_pages = search_cfg.get("language_pages", 3)
    for term in lang_terms:
        for lang in languages:
            queries.append((f"{term} language:{lang}", lang_pages))
    size_terms = search_cfg.get("size_terms", [])
    size_buckets = search_cfg.get("size_buckets", [])
    size_pages = search_cfg.get("size_pages", 5)
    for term in size_terms:
        for bucket in size_buckets:
            queries.append((f"{term} size:{bucket}", size_pages))
    compat_pages = search_cfg.get("compat_pages", 5)
    for q in search_cfg.get("compat_queries", []):
        queries.append((q, compat_pages))
    generic_pages = search_cfg.get("generic_pages", 3)
    for q in search_cfg.get("generic_queries", []):
        queries.append((q, generic_pages))
    cn_pages = search_cfg.get("cn_pages", 5)
    for q in search_cfg.get("cn_queries", []):
        queries.append((q, cn_pages))
    return queries


class SearchEngine:
    def __init__(self, *, client: httpx.AsyncClient, tokens: TokenPool,
                 queries: list[tuple[str, int]], pattern: re.Pattern, store,
                 candidates: asyncio.Queue, sweep_interval: int = 3600,
                 raw_concurrency: int = 10, stats=None,
                 deny: frozenset[str] = frozenset(),
                 alternate_indexed_sort: bool = True,
                 watch_content_re: re.Pattern | None = None,
                 watchlist_max: int = 0):
        self.client = client
        self.tokens = tokens
        self.queries = queries
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.sweep_interval = sweep_interval
        self.raw_sem = asyncio.Semaphore(raw_concurrency)
        self.stats = stats
        self.deny = deny
        self.alternate_indexed_sort = alternate_indexed_sort
        self.watch_content_re = watch_content_re
        self.watchlist_max = watchlist_max

    async def _api_headers(self):
        token = await self.tokens.acquire()
        headers = {
            "User-Agent": "deepseek-scanner",
            "Accept": "application/vnd.github+json",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def run(self, once: bool = False):
        while True:
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("search sweep failed")
            if once:
                return
            await asyncio.sleep(self.sweep_interval)

    def _load_done(self) -> set[int]:
        raw = self.store.kv_get("search_done")
        if not raw:
            return set()
        try:
            return {int(x) for x in json.loads(raw)}
        except (ValueError, TypeError):
            return set()

    def _mark_done(self, qi: int):
        done = self._load_done()
        done.add(qi)
        self.store.kv_set("search_done", json.dumps(sorted(done)))

    async def sweep(self):
        seen = set()
        parity = int(self.store.kv_get("sweep_parity") or 0) + 1
        self.store.kv_set("sweep_parity", str(parity))
        indexed_sort = self.alternate_indexed_sort and parity % 2 == 0
        done = self._load_done()

        queue: asyncio.Queue = asyncio.Queue()
        for qi, (query, pages) in enumerate(self.queries):
            if qi in done:
                continue
            queue.put_nowait((qi, query, pages))

        num_workers = max(1, self.tokens.size)
        log.info("sweep: %d/%d queries pending, %d parallel workers",
                 queue.qsize(), len(self.queries), num_workers)

        async def worker():
            while True:
                try:
                    qi, query, pages = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                if self.stats:
                    self.stats.search_query = query
                try:
                    completed = await self._run_query(qi, query, pages, seen,
                                                      indexed_sort)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log.exception("query failed, will retry next sweep: %r", query)
                    await asyncio.sleep(30)
                    continue
                if completed:
                    self._mark_done(qi)

        await asyncio.gather(*[worker() for _ in range(num_workers)],
                             return_exceptions=True)
        if len(self._load_done()) >= len(self.queries):
            self.store.kv_del("search_done")
        self.store.kv_del("search_cursor")

    async def _run_query(self, qi: int, query: str, max_pages: int,
                         seen: set, indexed_sort: bool) -> bool:
        log.info("searching: %s (indexed=%s)", query, indexed_sort)
        rate_limit_retries = 0
        raw_tasks: list = []
        try:
            for page in range(1, max_pages + 1):
                if self.stats:
                    self.stats.search_page = page
                    mark_beat(self.stats, "search", self.sweep_interval)
                headers = await self._api_headers()
                params = {"q": query, "per_page": 100, "page": page}
                if indexed_sort:
                    params["sort"] = "indexed"
                    params["order"] = "desc"
                try:
                    resp = await self.client.get(SEARCH_URL, params=params,
                                                 headers=headers, timeout=30.0)
                except httpx.HTTPError as exc:
                    log.warning("search request failed: %s", exc)
                    return False

                if self.stats:
                    remain = resp.headers.get("X-RateLimit-Remaining", "?")
                    limit = resp.headers.get("X-RateLimit-Limit", "?")
                    self.stats.search_rate = f"{remain}/{limit}"

                if resp.status_code == 403:
                    rate_limit_retries += 1
                    if rate_limit_retries > 2:
                        log.warning("search rate limited repeatedly, deferring query: %s", query)
                        return False
                    await self._handle_rate_limit(resp)
                    continue
                if resp.status_code == 422:
                    log.warning("search query rejected (422): %s", query)
                    return True
                if resp.status_code != 200:
                    log.warning("search HTTP %d for %s", resp.status_code, query)
                    return False

                try:
                    data = resp.json()
                except ValueError:
                    log.warning("search returned non-JSON for %r (page %d)", query, page)
                    return False
                items = data.get("items", [])
                if self.stats:
                    self.stats.search_results += len(items)
                log.info("query=%r page=%d results=%d total=%d", query, page,
                         len(items), data.get("total_count", 0))
                if not items:
                    return True

                for item in items:
                    repo = item.get("repository") or {}
                    full_name = repo.get("full_name")
                    branch = repo.get("default_branch") or "main"
                    path = item.get("path")
                    html_url = item.get("html_url")
                    sha = item.get("sha")
                    size_kb = repo.get("size")
                    if not full_name or not path:
                        continue
                    key = (full_name, path)
                    if key in seen:
                        continue
                    seen.add(key)
                    if sha and self.store.file_seen(full_name, path, sha):
                        continue
                    raw_tasks.append(self._scan_raw(full_name, branch, path, sha,
                                                    html_url, size_kb))

                if len(items) < 100:
                    return True
            return True
        finally:
            if raw_tasks:
                await asyncio.gather(*raw_tasks, return_exceptions=True)

    async def _scan_raw(self, full_name: str, branch: str, path: str,
                        sha: str | None, html_url: str | None,
                        size_kb: int | None):
        async with self.raw_sem:
            url = RAW_URL.format(repo=full_name, branch=branch, path=path)
            try:
                resp = await self.client.get(url, timeout=30.0, follow_redirects=True)
            except httpx.HTTPError as exc:
                log.debug("raw fetch failed %s: %s", url, exc)
                return
            if resp.status_code != 200:
                log.debug("raw fetch HTTP %d for %s", resp.status_code, url)
                return

            if sha:
                self.store.mark_file_seen(full_name, path, sha)

            text = resp.text
            if self.watch_content_re and self.watch_content_re.search(text):
                self.store.add_watchlist(full_name, size_kb,
                                         max_count=self.watchlist_max)

            for key in extract_keys(text, self.pattern):
                if is_placeholder(key, self.deny):
                    continue
                key_hash = hashlib.sha256(key.encode()).hexdigest()
                if self.store.add_candidate(
                    key_hash=key_hash,
                    key=key,
                    repo=full_name,
                    file_path=path,
                    commit_url=html_url,
                    author_name=None,
                    author_email=None,
                    source="search",
                ):
                    log.info("candidate from search: %s %s", full_name, path)
                    self.store.add_watchlist(full_name, size_kb, force=True)
                    if self.stats:
                        self.stats.candidates += 1
                    await self.candidates.put({
                        "key_hash": key_hash,
                        "key": key,
                        "repo": full_name,
                        "file_path": path,
                        "commit_url": html_url,
                        "author_name": None,
                        "author_email": None,
                        "source": "search",
                    })

    @staticmethod
    async def _handle_rate_limit(resp: httpx.Response):
        remain = resp.headers.get("X-RateLimit-Remaining")
        reset = resp.headers.get("X-RateLimit-Reset")
        wait = 60
        if reset:
            try:
                wait = max(1, int(reset) - int(time.time()) + 1)
            except ValueError:
                pass
        wait = min(wait, 120)
        log.warning("search rate limited (remaining=%s), sleeping %ds", remain, wait)
        await asyncio.sleep(wait)
