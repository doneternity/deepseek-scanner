import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone

import httpx

from scanner.diffscan import DiffScanner
from scanner.ratelimit import TokenBucket
from scanner.tokens import TokenPool
from scanner.ui import mark_beat

log = logging.getLogger("scanner.gh-search")

COMMITS_URL = "https://api.github.com/search/commits"
REPOS_URL = "https://api.github.com/search/repositories"


def days_ago_date(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")


def today_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def sanitize_cursor(cursor: str | None, lookback_days: int) -> str:
    if not cursor:
        return days_ago_date(lookback_days)
    value = cursor[:10]
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return days_ago_date(lookback_days)
    today = today_date()
    if value > today:
        return today
    return value


def prev_day(date_str: str) -> str:
    dt = datetime.strptime(date_str[:10], "%Y-%m-%d") - timedelta(days=1)
    return dt.strftime("%Y-%m-%d")


def advance_cursor(current: str, dates: list[str]) -> str:
    today = today_date()
    vals = [d[:10] for d in dates if d and d[:10] <= today]
    if not vals:
        return current
    newest = max(vals)
    return newest if newest > current else current


class CommitSearchEngine:
    def __init__(self, *, client: httpx.AsyncClient, tokens: TokenPool,
                 store, candidates, patch_bucket: TokenBucket,
                 pattern: re.Pattern, queries: list[str],
                 generic_queries: list[str] | None = None,
                 lookback_days: int = 30, pages: int = 3,
                 generic_pages: int = 3,
                 interval_seconds: int = 900, stats=None,
                 deny: frozenset[str] = frozenset(), hot: bool = True):
        self.client = client
        self.tokens = tokens
        self.store = store
        self.candidates = candidates
        self.query_list: list[tuple[str, int]] = [(q, pages) for q in queries]
        self.query_list += [(q, generic_pages) for q in (generic_queries or [])]
        self.lookback_days = lookback_days
        self.interval_seconds = interval_seconds
        self.stats = stats
        self.scanner = DiffScanner(
            client=client, pattern=pattern, store=store, candidates=candidates,
            patch_bucket=patch_bucket, stats=stats, deny=deny,
            source="commit-search", hot=hot,
        )

    async def _api_headers(self):
        token = await self.tokens.acquire()
        headers = {"User-Agent": "deepseek-scanner",
                   "Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def run(self):
        while True:
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("commit search sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        for qi, (query, max_pages) in enumerate(self.query_list):
            cursor_key = f"commit_search_cursor_{qi}"
            stored = self.store.kv_get(cursor_key)
            cursor = sanitize_cursor(stored, self.lookback_days)
            if stored != cursor:
                self.store.kv_set(cursor_key, cursor)
            query_cursor = prev_day(cursor)
            for page in range(1, max_pages + 1):
                if self.stats:
                    mark_beat(self.stats, "commit-search", self.interval_seconds)
                headers = await self._api_headers()
                params = {"q": f"{query} committer-date:>{query_cursor}",
                          "per_page": 100, "page": page,
                          "sort": "committer-date", "order": "desc"}
                try:
                    resp = await self.client.get(COMMITS_URL, params=params,
                                                 headers=headers, timeout=30.0)
                except httpx.HTTPError as exc:
                    log.warning("commit search failed: %s", exc)
                    break
                if resp.status_code == 403:
                    log.warning("commit search rate limited, backing off")
                    await asyncio.sleep(65)
                    break
                if resp.status_code == 422:
                    log.warning("commit search query rejected: %r", query)
                    break
                if resp.status_code != 200:
                    log.warning("commit search HTTP %d", resp.status_code)
                    break
                try:
                    items = resp.json().get("items", [])
                except ValueError:
                    break
                if self.stats:
                    self.stats.commit_hits += len(items)
                log.info("commit search %r: %d results", query, len(items))
                if not items:
                    break

                dates = []
                tasks = []
                for item in items:
                    repo = (item.get("repository") or {}).get("full_name")
                    sha = item.get("sha")
                    date = (((item.get("commit") or {}).get("committer") or {})
                            .get("date"))
                    if date:
                        dates.append(date)
                    if repo and sha:
                        tasks.append(self.scanner.scan_push(repo, None, sha))
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                self.store.kv_set(cursor_key, advance_cursor(cursor, dates))
                cursor = self.store.kv_get(cursor_key) or cursor
                if len(items) < 100:
                    break


class RepoSearchEngine:
    def __init__(self, *, client: httpx.AsyncClient, tokens: TokenPool,
                 store, queries: list[str], lookback_days: int = 90,
                 pages: int = 2, interval_seconds: int = 3600, stats=None,
                 watchlist_max: int = 0):
        self.client = client
        self.tokens = tokens
        self.store = store
        self.queries = queries
        self.lookback_days = lookback_days
        self.pages = pages
        self.interval_seconds = interval_seconds
        self.stats = stats
        self.watchlist_max = watchlist_max

    async def _api_headers(self):
        token = await self.tokens.acquire()
        headers = {"User-Agent": "deepseek-scanner",
                   "Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def run(self):
        while True:
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("repo search sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        for qi, query in enumerate(self.queries):
            cursor_key = f"repo_search_cursor_{qi}"
            stored = self.store.kv_get(cursor_key)
            cursor = sanitize_cursor(stored, self.lookback_days)
            if stored != cursor:
                self.store.kv_set(cursor_key, cursor)
            query_cursor = prev_day(cursor)
            for page in range(1, self.pages + 1):
                if self.stats:
                    mark_beat(self.stats, "repo-search", self.interval_seconds)
                headers = await self._api_headers()
                params = {"q": f"{query} pushed:>{query_cursor}",
                          "per_page": 100, "page": page,
                          "sort": "updated", "order": "desc"}
                try:
                    resp = await self.client.get(REPOS_URL, params=params,
                                                 headers=headers, timeout=30.0)
                except httpx.HTTPError as exc:
                    log.warning("repo search failed: %s", exc)
                    break
                if resp.status_code == 403:
                    log.warning("repo search rate limited, backing off")
                    await asyncio.sleep(65)
                    break
                if resp.status_code == 422:
                    log.warning("repo search query rejected: %r", query)
                    break
                if resp.status_code != 200:
                    log.warning("repo search HTTP %d", resp.status_code)
                    break
                try:
                    items = resp.json().get("items", [])
                except ValueError:
                    break
                if self.stats:
                    self.stats.repo_hits += len(items)
                log.info("repo search %r: %d repos", query, len(items))
                if not items:
                    break

                dates = []
                for item in items:
                    full_name = item.get("full_name")
                    size_kb = item.get("size")
                    pushed = item.get("pushed_at")
                    if pushed:
                        dates.append(pushed)
                    if not full_name:
                        continue
                    self.store.add_watchlist(full_name, size_kb,
                                             max_count=self.watchlist_max)
                self.store.kv_set(cursor_key, advance_cursor(cursor, dates))
                cursor = self.store.kv_get(cursor_key) or cursor
                if len(items) < 100:
                    break
