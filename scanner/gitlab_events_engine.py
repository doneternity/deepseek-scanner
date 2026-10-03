import asyncio
import hashlib
import logging
import re
from datetime import datetime, timedelta, timezone

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.gitlab-events")


class GitlabEventsEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, stats=None, deny: frozenset[str] = frozenset(),
                 token: str = "", host: str = "https://gitlab.com",
                 poll_interval: int = 60):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.stats = stats
        self.deny = deny
        self.token = token
        self.host = host.rstrip("/")
        self.poll_interval = poll_interval
        self.bucket = TokenBucket(rate=1.0, capacity=30)

    def _headers(self):
        return {"User-Agent": "deepseek-scanner", "PRIVATE-TOKEN": self.token}

    async def run(self):
        while True:
            try:
                await self.poll()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("gitlab events poll failed")
            await asyncio.sleep(self.poll_interval)

    async def poll(self):
        cursor = self.store.kv_get("gitlab_events_cursor")
        if not cursor:
            cursor = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        params = {"action": "pushed", "per_page": 100, "after": cursor}
        try:
            resp = await self.client.get(f"{self.host}/api/v4/events",
                                         params=params, headers=self._headers(),
                                         timeout=30.0)
        except httpx.HTTPError as exc:
            log.warning("gitlab events request failed: %s", exc)
            return
        if resp.status_code in (401, 403):
            log.warning("gitlab events token rejected")
            return
        if self.stats:
            mark_beat(self.stats, "gitlab-events", self.poll_interval)
        if resp.status_code != 200:
            log.warning("gitlab events HTTP %d", resp.status_code)
            return
        try:
            events = resp.json()
        except ValueError:
            log.warning("gitlab events returned non-JSON")
            return
        if not isinstance(events, list):
            return

        if events:
            newest = max(e.get("created_at", cursor) for e in events)
            self.store.kv_set("gitlab_events_cursor", newest)
        if self.stats:
            self.stats.gitlab_events += len(events)
        log.info("gitlab events: %d pushes", len(events))
        await asyncio.gather(*[self._process_event(e) for e in events],
                             return_exceptions=True)

    async def _process_event(self, event: dict):
        project_id = event.get("project_id")
        push = event.get("push_data") or {}
        ref = push.get("ref")
        from_sha = push.get("commit_from")
        to_sha = push.get("commit_to")
        if not project_id or not ref or not to_sha:
            return

        await self.bucket.acquire()
        url = f"{self.host}/api/v4/projects/{project_id}/repository/compare"
        params = {"from": from_sha, "to": to_sha}
        try:
            resp = await self.client.get(url, params=params, headers=self._headers(),
                                         timeout=30.0)
        except httpx.HTTPError:
            return
        if resp.status_code != 200:
            return
        try:
            compare = resp.json()
        except ValueError:
            return

        diffs = compare.get("diffs") or []
        matches: list[tuple[str, str]] = []
        for d in diffs:
            path = d.get("new_path")
            for line in (d.get("diff") or "").splitlines():
                if not line.startswith("+") or line.startswith("+++"):
                    continue
                for key in extract_keys(line[1:], self.pattern):
                    if is_placeholder(key, self.deny):
                        continue
                    matches.append((path, key))

        if not matches:
            return

        repo_name = None
        web_url = None
        await self.bucket.acquire()
        try:
            proj = await self.client.get(
                f"{self.host}/api/v4/projects/{project_id}",
                headers=self._headers(), timeout=30.0)
            if proj.status_code == 200:
                data = proj.json()
                repo_name = data.get("path_with_namespace")
                web_url = data.get("web_url")
        except httpx.HTTPError:
            pass

        for path, key in matches:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            if not self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=repo_name or f"gitlab:{project_id}",
                file_path=path,
                commit_url=web_url,
                author_name=None,
                author_email=None,
                source="gitlab-events",
            ):
                continue
            log.info("candidate from gitlab push: %s %s", repo_name, path)
            if self.stats:
                self.stats.candidates += 1
            await self.candidates.put({
                "key_hash": key_hash,
                "key": key,
                "repo": repo_name or f"gitlab:{project_id}",
                "file_path": path,
                "commit_url": web_url,
                "author_name": None,
                "author_email": None,
                "source": "gitlab-events",
                "priority": "hot",
            })
