import asyncio
import hashlib
import logging
import re
import urllib.parse

import httpx

from scanner.filters import extract_keys, is_placeholder
from scanner.ratelimit import TokenBucket
from scanner.ui import mark_beat

log = logging.getLogger("scanner.dockerhub")

HUB_SEARCH = "https://hub.docker.com/v2/search/repositories/"
TOKEN_URL = "https://auth.docker.io/token"
REGISTRY = "https://registry-1.docker.io/v2/{name}"
MANIFEST_ACCEPT = (", ".join([
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
]))


class DockerHubEngine:
    def __init__(self, *, client: httpx.AsyncClient, pattern: re.Pattern, store,
                 candidates, queries: list[str] | None = None,
                 max_images: int = 30, max_tags: int = 4,
                 interval_seconds: int = 86400,
                 stats=None, deny: frozenset[str] = frozenset()):
        self.client = client
        self.pattern = pattern
        self.store = store
        self.candidates = candidates
        self.queries = queries or ["deepseek"]
        self.max_images = max_images
        self.max_tags = max(1, max_tags)
        self.interval_seconds = interval_seconds
        self.stats = stats
        self.deny = deny
        self.bucket = TokenBucket(rate=0.5, capacity=5)

    async def run(self):
        while True:
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("dockerhub sweep failed")
            await asyncio.sleep(self.interval_seconds)

    async def sweep(self):
        names = []
        for query in self.queries:
            await self.bucket.acquire()
            try:
                resp = await self.client.get(HUB_SEARCH,
                                             params={"query": query,
                                                     "page_size": 25},
                                             timeout=30.0)
            except httpx.HTTPError as exc:
                log.warning("dockerhub search failed: %s", exc)
                continue
            if resp.status_code != 200:
                log.warning("dockerhub search HTTP %d", resp.status_code)
                continue
            try:
                results = resp.json().get("results") or []
            except ValueError:
                continue
            names.extend(x.get("repo_name") for x in results if x.get("repo_name"))
        names = names[:self.max_images]
        if self.stats:
            mark_beat(self.stats, "dockerhub", self.interval_seconds)
        log.info("dockerhub: scanning %d image configs", len(names))
        scanned = 0
        for name in names:
            try:
                await self._scan_image(name)
                scanned += 1
            except Exception:
                log.exception("dockerhub image scan failed: %s", name)
        log.info("dockerhub: done scanning %d images (%d tags max each)",
                 scanned, self.max_tags)

    async def _scan_image(self, name: str):
        if self.stats:
            self.stats.docker_images += 1
        tags = await self._fetch_tags(name)
        await self.bucket.acquire()
        try:
            tok = await self.client.get(TOKEN_URL, params={
                "service": "registry.docker.io",
                "scope": f"repository:{name}:pull"}, timeout=20.0)
            token = tok.json().get("token")
        except (httpx.HTTPError, ValueError):
            return
        if not token:
            return
        for tag in tags:
            try:
                await self._scan_tag(name, token, tag)
            except Exception:
                log.debug("dockerhub tag scan failed: %s:%s", name, tag)

    async def _fetch_tags(self, name: str) -> list[str]:
        await self.bucket.acquire()
        try:
            resp = await self.client.get(
                f"https://hub.docker.com/v2/repositories/{name}/tags",
                params={"page_size": self.max_tags, "ordering": "last_updated"},
                timeout=30.0)
            if resp.status_code == 200:
                results = resp.json().get("results") or []
                tags = [r.get("name") for r in results if r.get("name")]
                if tags:
                    return tags[:self.max_tags]
        except (httpx.HTTPError, ValueError):
            pass
        return ["latest"]

    async def _scan_tag(self, name: str, token: str, tag: str):
        headers = {"User-Agent": "deepseek-scanner",
                   "Authorization": f"Bearer {token}",
                   "Accept": MANIFEST_ACCEPT}
        await self.bucket.acquire()
        try:
            resp = await self.client.get(
                f"{REGISTRY.format(name=name)}/manifests/{tag}",
                headers=headers, timeout=30.0)
        except httpx.HTTPError:
            return
        if resp.status_code != 200:
            return
        try:
            manifest = resp.json()
        except ValueError:
            return
        if "manifests" in manifest:
            amd = next((m for m in manifest["manifests"]
                        if (m.get("platform") or {}).get("architecture") == "amd64"),
                       None)
            if not amd:
                return
            await self.bucket.acquire()
            try:
                resp = await self.client.get(
                    f"{REGISTRY.format(name=name)}/manifests/{amd['digest']}",
                    headers=headers, timeout=30.0)
                manifest = resp.json()
            except (httpx.HTTPError, ValueError):
                return
        digest = (manifest.get("config") or {}).get("digest")
        if not digest:
            return
        if self.store.file_seen("docker", f"{name}:{tag}", digest):
            return
        await self.bucket.acquire()
        try:
            blob = await self.client.get(
                f"{REGISTRY.format(name=name)}/blobs/{digest}",
                headers=headers, timeout=30.0, follow_redirects=True)
        except httpx.HTTPError:
            return
        if blob.status_code != 200 or len(blob.content) > 5_000_000:
            return
        self.store.mark_file_seen("docker", f"{name}:{tag}", digest)

        for key in extract_keys(blob.text, self.pattern):
            if is_placeholder(key, self.deny):
                continue
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            if not self.store.add_candidate(
                key_hash=key_hash,
                key=key,
                repo=f"docker.io/{name}",
                file_path=f"image config ({tag})",
                commit_url=f"https://hub.docker.com/r/{name}",
                author_name=None,
                author_email=None,
                source="dockerhub",
            ):
                continue
            log.info("candidate from dockerhub: %s:%s", name, tag)
            if self.stats:
                self.stats.candidates += 1
            self.candidates.put_nowait({
                "key_hash": key_hash,
                "key": key,
                "repo": f"docker.io/{name}",
                "file_path": f"image config ({tag})",
                "commit_url": f"https://hub.docker.com/r/{name}",
                "author_name": None,
                "author_email": None,
                "source": "dockerhub",
                "priority": "cold",
            })
