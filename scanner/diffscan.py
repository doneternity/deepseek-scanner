import asyncio
import hashlib
import logging
import re

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.ratelimit import TokenBucket

log = logging.getLogger("scanner.diffscan")

PATCH_URL = "https://github.com/{repo}/commit/{sha}.patch"
COMPARE_URL = "https://github.com/{repo}/compare/{before}...{head}.diff"
FROM_RE = re.compile(r"^(.*?)\s*<([^>]+)>$")


def iter_added_lines(text: str):
    current_file = None
    for line in text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split(" ")
            b = parts[3] if len(parts) > 3 else None
            if b and b.startswith("b/"):
                current_file = b[2:]
            else:
                current_file = None
            continue
        if line.startswith("+++ "):
            target = line[4:]
            if target.startswith("b/"):
                current_file = target[2:]
            continue
        if line.startswith("+") and not line.startswith("+++"):
            yield current_file, line[1:]


def parse_from(text: str) -> tuple[str | None, str | None]:
    for line in text.splitlines():
        if not line.startswith("From: "):
            continue
        rest = line[6:].strip()
        m = FROM_RE.match(rest)
        if m:
            return m.group(1).strip(), m.group(2)
        return rest, None
    return None, None


class DiffScanner:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, patch_bucket: TokenBucket, stats=None,
                 deny: frozenset[str] = frozenset(), source: str = "events",
                 hot: bool = True):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.patch_bucket = patch_bucket
        self.stats = stats
        self.deny = deny
        self.source = source
        self.hot = hot

    async def scan_push(self, repo: str, before: str | None, head: str) -> bool:
        if self.store.sha_processed(head):
            return True
        if before and before != "0" * 40:
            text = await self._fetch(COMPARE_URL.format(repo=repo, before=before, head=head))
            if text is None:
                text = await self._fetch(PATCH_URL.format(repo=repo, sha=head))
        else:
            text = await self._fetch(PATCH_URL.format(repo=repo, sha=head))
        if text is None:
            return False

        matches: list[dict] = []
        for path, added in iter_added_lines(text):
            for key in extract_keys(added, self.pattern):
                if is_placeholder(key, self.deny):
                    continue
                matches.append({"key": key, "file_path": path})

        if not matches:
            self.store.add_processed_shas([head])
            return True

        author_name = author_email = None
        head_patch = await self._fetch(PATCH_URL.format(repo=repo, sha=head))
        if head_patch:
            author_name, author_email = parse_from(head_patch)

        commit_url = f"https://github.com/{repo}/commit/{head}"
        for m in matches:
            key = m["key"]
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            if not self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=repo,
                file_path=m["file_path"],
                commit_url=commit_url,
                author_name=author_name,
                author_email=author_email,
                source=self.source,
            ):
                continue
            log.info("candidate from %s: %s @ %s", self.source, repo, head)
            if self.stats:
                self.stats.candidates += 1
            await self.candidates.put({
                "key_hash": key_hash,
                "key": key,
                "repo": repo,
                "file_path": m["file_path"],
                "commit_url": commit_url,
                "author_name": author_name,
                "author_email": author_email,
                "source": self.source,
                "priority": "hot" if self.hot else "cold",
            })
        self.store.add_processed_shas([head])
        return True

    async def _fetch(self, url: str) -> str | None:
        await self.patch_bucket.acquire()
        headers = {"User-Agent": "deepseek-scanner"}
        try:
            resp = await self.client.get(url, headers=headers, timeout=30.0,
                                         follow_redirects=True)
        except httpx.HTTPError as exc:
            log.debug("diff fetch failed %s: %s", url, exc)
            return None
        if resp.status_code == 429:
            log.warning("patch endpoint rate limited, backing off 30s")
            await asyncio.sleep(30)
            return None
        if resp.status_code != 200:
            log.debug("diff HTTP %d for %s", resp.status_code, url)
            return None
        return resp.text
