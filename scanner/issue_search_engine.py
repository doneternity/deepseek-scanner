import asyncio
import hashlib
import logging
import re

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.gh_search_engine import (advance_cursor, prev_day,
                                      sanitize_cursor)
from scanner.tokens import TokenPool
from scanner.ui import mark_beat

log = logging.getLogger("scanner.issue-search")

SEARCH_URL = "https://api.github.com/search/issues"


class IssueSearchEngine:
    def __init__(self, *, client: httpx.AsyncClient, search_tokens: TokenPool,
                 core_tokens: TokenPool, store, candidates, pattern: re.Pattern,
                 queries: list[str] | None = None, pages: int = 2,
                 lookback_days: int = 30, interval_seconds: int = 1800,
                 max_comment_fetches: int = 30, stats=None,
                 deny: frozenset[str] = frozenset(), hot: bool = True):
        self.client = client
        self.search_tokens = search_tokens
        self.core_tokens = core_tokens
        self.store = store
        self.candidates = candidates
        self.pattern = pattern
        self.queries = queries or ["DEEPSEEK_API_KEY", '"api.deepseek.com"',
                                   "deepseek_apikey", "DEEPSEEK_API_KEY sk-"]
        self.pages = pages
        self.lookback_days = lookback_days
        self.interval_seconds = interval_seconds
        self.max_comment_fetches = max_comment_fetches
        self.stats = stats
        self.deny = deny
        self.hot = hot

    async def _search_headers(self):
        token = await self.search_tokens.acquire()
        headers = {"User-Agent": "deepseek-scanner",
                   "Accept": "application/vnd.github.text-match+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def _core_headers(self):
        token = await self.core_tokens.acquire()
        headers = {"User-Agent": "deepseek-scanner"}
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
                log.exception("issue search sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        comment_budget = self.max_comment_fetches
        for qi, query in enumerate(self.queries):
            cursor_key = f"issue_search_cursor_{qi}"
            stored = self.store.kv_get(cursor_key)
            cursor = sanitize_cursor(stored, self.lookback_days)
            if stored != cursor:
                self.store.kv_set(cursor_key, cursor)
            query_cursor = prev_day(cursor)
            for page in range(1, self.pages + 1):
                if self.stats:
                    mark_beat(self.stats, "issue-search", self.interval_seconds)
                headers = await self._search_headers()
                params = {"q": f"{query} created:>{query_cursor}", "per_page": 100,
                          "page": page, "sort": "created", "order": "desc"}
                try:
                    resp = await self.client.get(SEARCH_URL, params=params,
                                                 headers=headers, timeout=30.0)
                except httpx.HTTPError as exc:
                    log.warning("issue search failed: %s", exc)
                    break
                if resp.status_code == 403:
                    log.warning("issue search rate limited, backing off")
                    await asyncio.sleep(65)
                    break
                if resp.status_code == 422:
                    log.warning("issue search query rejected: %r", query)
                    break
                if resp.status_code != 200:
                    log.warning("issue search HTTP %d", resp.status_code)
                    break
                try:
                    items = resp.json().get("items", [])
                except ValueError:
                    break
                if self.stats:
                    self.stats.issue_hits += len(items)
                log.info("issue search %r: %d results", query, len(items))
                if not items:
                    break

                dates = []
                for item in items:
                    created = item.get("created_at")
                    if created:
                        dates.append(created)
                    text = item.get("body") or ""
                    for frag in item.get("text_matches") or []:
                        text += "\n" + (frag.get("fragment") or "")
                    found = self._scan_text(item, text)
                    if (not found and item.get("comments", 0) > 0
                            and comment_budget > 0):
                        comment_budget -= 1
                        await self._fetch_comments(item)
                self.store.kv_set(cursor_key, advance_cursor(cursor, dates))
                cursor = self.store.kv_get(cursor_key) or cursor
                if len(items) < 100:
                    break

    async def _fetch_comments(self, item: dict):
        url = item.get("comments_url")
        if not url:
            return
        headers = await self._core_headers()
        try:
            resp = await self.client.get(url, params={"per_page": 100},
                                         headers=headers, timeout=30.0)
        except httpx.HTTPError:
            return
        if resp.status_code != 200:
            return
        try:
            comments = resp.json()
        except ValueError:
            return
        if not isinstance(comments, list):
            return
        text = "\n".join(c.get("body") or "" for c in comments)
        self._scan_text(item, text)

    def _scan_text(self, item: dict, text: str) -> bool:
        found = False
        for key in extract_keys(text or "", self.pattern):
            if is_placeholder(key, self.deny):
                continue
            found = True
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            repo = "issue"
            repo_url = item.get("repository_url") or ""
            if "/repos/" in repo_url:
                repo = repo_url.split("/repos/", 1)[1]
            elif "/repositories/" in repo_url:
                repo = repo_url.split("/repositories/", 1)[1]
            author = (item.get("user") or {}).get("login")
            if not self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=repo,
                file_path=item.get("title"),
                commit_url=item.get("html_url"),
                author_name=author,
                author_email=None,
                source="issue-search",
            ):
                continue
            log.info("candidate from issue search: %s", item.get("html_url"))
            if self.stats:
                self.stats.candidates += 1
            self.candidates.put_nowait({
                "key_hash": key_hash,
                "key": key,
                "repo": repo,
                "file_path": item.get("title"),
                "commit_url": item.get("html_url"),
                "author_name": author,
                "author_email": None,
                "source": "issue-search",
                "priority": "hot" if self.hot else "cold",
            })
        return found
