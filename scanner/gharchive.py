import asyncio
import gzip
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone

import httpx

from scanner.diffscan import DiffScanner
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.gharchive")

ARCHIVE_URL = "https://data.gharchive.org/{date}-{hour}.json.gz"


def event_matches(event: dict, terms: list[str]) -> bool:
    if event.get("type") != "PushEvent":
        return False
    payload = event.get("payload") or {}
    haystack = json.dumps(payload, separators=(",", ":")).lower()
    return any(term in haystack for term in terms)


class GHArchiveEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, patch_bucket: TokenBucket, stats=None,
                 deny: frozenset[str] = frozenset(),
                 signal_terms: list[str] | None = None,
                 backfill_days: int = 7, hot: bool = True,
                 concurrency: int = 5):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.stats = stats
        self.deny = deny
        self.signal_terms = [t.lower() for t in (signal_terms or [
            "deepseek", "DEEPSEEK_API_KEY", "api.deepseek.com", "sk-"])]
        self.backfill_days = backfill_days
        self.scanner = DiffScanner(
            client=client, pattern=pattern, store=store, candidates=candidates,
            patch_bucket=patch_bucket, stats=stats, deny=deny,
            source="gharchive", hot=hot,
        )
        self.sem = asyncio.Semaphore(concurrency)
        self.cursor_hour = None

    async def run(self):
        if self.backfill_days > 0:
            try:
                await self.backfill(self.backfill_days)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("gharchive backfill failed")
        while True:
            try:
                await self._advance()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("gharchive poll failed")
            await asyncio.sleep(600)

    async def backfill(self, days: int):
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        hours = [now - timedelta(hours=i) for i in range(days * 24)]
        log.info("gharchive backfill: %d hour files", len(hours))
        await asyncio.gather(*[self._process_hour(dt) for dt in hours],
                             return_exceptions=True)

    async def process_latest(self):
        now = datetime.now(timezone.utc) - timedelta(minutes=15)
        await self._process_hour(now.replace(minute=0, second=0, microsecond=0))

    async def _advance(self) -> bool:
        now_hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        if self.cursor_hour is None:
            self.cursor_hour = now_hour - timedelta(hours=1)
        progressed = False
        while self.cursor_hour <= now_hour - timedelta(hours=1):
            ok = await self._process_hour(self.cursor_hour)
            if not ok:
                return progressed
            self.cursor_hour += timedelta(hours=1)
            progressed = True
        return progressed

    async def _process_hour(self, dt: datetime) -> bool:
        if self.stats:
            mark_beat(self.stats, "gharchive", 600)
        key = dt.strftime("%Y-%m-%d-%H")
        done_key = f"gharchive_done_{key}"
        if self.store.kv_get(done_key):
            return True
        current = self.store.kv_get("gharchive_last_file")
        if current and key <= current:
            return True
        url = ARCHIVE_URL.format(date=dt.strftime("%Y-%m-%d"), hour=dt.hour)
        async with self.sem:
            events = await self._download_and_filter(url)
            if events is None:
                return False
            if self.stats:
                self.stats.gharchive_files += 1
            log.info("gharchive %s: %d signal pushes", key, len(events))
            for repo, before, head in events:
                try:
                    await self.scanner.scan_push(repo, before, head)
                except Exception:
                    log.exception("gharchive scan failed for %s @ %s", repo, head)
            self.store.kv_set(done_key, "1")
            return True

    async def _download_and_filter(self, url: str) -> list[tuple[str, str, str]] | None:
        headers = {"User-Agent": "deepseek-scanner"}
        tmp = None
        try:
            resp = await self.client.get(url, headers=headers, timeout=120.0,
                                         follow_redirects=True)
            if resp.status_code != 200:
                log.debug("gharchive HTTP %d for %s", resp.status_code, url)
                return None
            fd, tmp = tempfile.mkstemp(suffix=".json.gz")
            os.close(fd)
            with open(tmp, "wb") as fh:
                async for chunk in resp.aiter_bytes():
                    fh.write(chunk)
            pushes = await asyncio.to_thread(self._filter_file, tmp)
            return pushes
        except httpx.HTTPError as exc:
            log.warning("gharchive download failed %s: %s", url, exc)
            return None
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def _filter_file(self, path: str) -> list[tuple[str, str, str]]:
        pushes = []
        terms = self.signal_terms
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            for line in fh:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if not event_matches(event, terms):
                    continue
                repo = (event.get("repo") or {}).get("name")
                payload = event.get("payload") or {}
                head = payload.get("head")
                if not repo or not head:
                    continue
                pushes.append((repo, payload.get("before"), head))
        return pushes
