import asyncio
import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time

from scanner.filters import extract_keys, is_placeholder
from scanner.ui import mark_beat

log = logging.getLogger("scanner.clone")

CLONE_TIMEOUT = 240
GREP_TIMEOUT = 180
MAX_MATCHES = 50
MAX_REVS = 3000
MAX_CLONE_FAILURES = 3


class CloneEngine:
    def __init__(self, *, store, pattern: re.Pattern,
                 candidates: asyncio.Queue, stats=None,
                 deny: frozenset[str] = frozenset(),
                 max_concurrent: int = 2, max_repo_size_mb: int = 500,
                 rescan_days: int = 7):
        self.store = store
        self.pattern = pattern
        self.candidates = candidates
        self.stats = stats
        self.deny = deny
        self.sem = asyncio.Semaphore(max_concurrent)
        self.max_repo_size_mb = max_repo_size_mb
        self.rescan_days = rescan_days
        self.enabled = shutil.which("git") is not None
        if not self.enabled:
            log.warning("git binary not found, clone engine disabled")

    async def run(self):
        if not self.enabled:
            return
        while True:
            try:
                await self.cycle()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("clone cycle failed")
            await asyncio.sleep(30)

    async def cycle(self):
        repos = self.store.watchlist_due(self.rescan_days,
                                         self.max_repo_size_mb * 1024, limit=8)
        if self.stats:
            mark_beat(self.stats, "clone", 60)
        if not repos:
            return
        log.info("clone cycle: %d repos due", len(repos))
        await asyncio.gather(
            *[self._scan_repo(repo) for repo in repos],
            return_exceptions=True,
        )

    async def _scan_repo(self, repo: str):
        async with self.sem:
            with tempfile.TemporaryDirectory(prefix="clone-",
                                             ignore_cleanup_errors=True) as td:
                repo_dir = os.path.join(td, "repo")
                url = f"https://github.com/{repo}"
                ok = await asyncio.to_thread(self._git_clone, url, repo_dir)
                if not ok:
                    fails = self.store.mark_watchlist_failed(repo)
                    log.warning("clone failed for %s (fail %d/%d)", repo, fails,
                                MAX_CLONE_FAILURES)
                    if fails >= MAX_CLONE_FAILURES:
                        self.store.mark_watchlist_scanned(repo)
                    return

                try:
                    matches = await asyncio.to_thread(self._git_grep, repo_dir)
                except Exception:
                    log.exception("git grep failed for %s", repo)
                    matches = []

                for path, key in matches:
                    key_hash = hashlib.sha256(key.encode()).hexdigest()
                    sha, name, email = await asyncio.to_thread(
                        self._find_commit, repo_dir, key)
                    commit_url = f"https://github.com/{repo}/commit/{sha}" if sha else None
                    if self.store.add_candidate(
                        key_hash=key_hash,
                        key=key,
                        repo=repo,
                        file_path=path,
                        commit_url=commit_url,
                        author_name=name,
                        author_email=email,
                        source="clone",
                    ):
                        log.info("candidate from history: %s %s", repo, path)
                        if self.stats:
                            self.stats.candidates += 1
                        await self.candidates.put({
                            "key_hash": key_hash,
                            "key": key,
                            "repo": repo,
                            "file_path": path,
                            "commit_url": commit_url,
                            "author_name": name,
                            "author_email": email,
                            "source": "clone",
                        })

                self.store.mark_watchlist_scanned(repo)
                if self.stats:
                    self.stats.clone_repos += 1
                log.info("history scan done: %s (%d matches)", repo, len(matches))

    def _git_clone(self, url: str, dest: str) -> bool:
        try:
            proc = subprocess.run(
                ["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout",
                 url, dest],
                capture_output=True, timeout=CLONE_TIMEOUT,
            )
            return proc.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def _git_grep(self, repo_dir: str) -> list[tuple[str, str]]:
        revs = subprocess.run(
            ["git", "-C", repo_dir, "rev-list", "--all"],
            capture_output=True, text=True, timeout=60,
        ).stdout.split()
        revs = revs[:MAX_REVS]
        if not revs:
            return []

        results: list[tuple[str, str]] = []
        seen_keys: set[str] = set()
        self._run_grep(repo_dir, self.pattern.pattern, revs, results, seen_keys)
        if len(results) < MAX_MATCHES:
            self._run_grep(repo_dir, r"atob\(|b64decode\(", revs, results,
                           seen_keys)
        return results

    def _run_grep(self, repo_dir: str, regex: str, revs: list[str],
                  results: list[tuple[str, str]], seen_keys: set[str]):
        proc = subprocess.Popen(
            ["git", "-C", repo_dir, "grep", "-n", "-E", regex, *revs],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        deadline = time.monotonic() + GREP_TIMEOUT
        try:
            for line in proc.stdout:
                if time.monotonic() > deadline:
                    log.warning("git grep timed out after %ds", GREP_TIMEOUT)
                    break
                rev, sep, rest = line.partition(":")
                if not sep:
                    continue
                path, sep2, content = rest.partition(":")
                if not sep2:
                    continue
                for key in extract_keys(content, self.pattern):
                    if is_placeholder(key, self.deny) or key in seen_keys:
                        continue
                    seen_keys.add(key)
                    results.append((path, key))
                    if len(results) >= MAX_MATCHES:
                        return
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _find_commit(self, repo_dir: str, key: str) -> tuple[str | None, str | None, str | None]:
        try:
            proc = subprocess.run(
                ["git", "-C", repo_dir, "log", "--all", "--format=%H|%an|%ae",
                 "-S", key, "-1"],
                capture_output=True, text=True, timeout=60,
            )
        except (subprocess.SubprocessError, OSError):
            return None, None, None
        line = proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""
        if not line:
            return None, None, None
        parts = line.split("|")
        sha = parts[0] if parts else None
        name = parts[1] if len(parts) > 1 else None
        email = parts[2] if len(parts) > 2 else None
        return sha, name, email
