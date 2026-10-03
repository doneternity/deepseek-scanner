import asyncio
import re
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from scanner import filters, validator
from scanner.clone_engine import CloneEngine
from scanner.diffscan import DiffScanner, iter_added_lines, parse_from
from scanner.fx import CurrencyConverter, FALLBACK_RATES
from scanner.gh_search_engine import (CommitSearchEngine, RepoSearchEngine,
                                      advance_cursor, days_ago_date, prev_day,
                                      sanitize_cursor)
from scanner.gharchive import GHArchiveEngine, event_matches
from scanner.notifier import Notifier
from scanner.pkgscan import scan_archive
from scanner.ratelimit import TokenBucket
from scanner.search_engine import SearchEngine, build_query_list
from scanner.storage import Store
from scanner.tokens import TokenPool


class TestStore:
    def test_kv_roundtrip(self, tmp_path):
        s = Store(str(tmp_path / "t.db"))
        assert s.kv_get("missing") is None
        s.kv_set("k", "v1")
        s.kv_set("k", "v2")
        assert s.kv_get("k") == "v2"
        s.kv_del("k")
        assert s.kv_get("k") is None
        s.close()

    def test_file_seen(self, tmp_path):
        s = Store(str(tmp_path / "t.db"))
        assert not s.file_seen("r", "f.py", "sha1")
        s.mark_file_seen("r", "f.py", "sha1")
        assert s.file_seen("r", "f.py", "sha1")
        assert not s.file_seen("r", "f.py", "sha2")
        s.mark_file_seen("r", "f.py", "sha2")
        assert s.file_seen("r", "f.py", "sha2")
        s.close()

    def test_gist_seen(self, tmp_path):
        s = Store(str(tmp_path / "t.db"))
        assert not s.gist_seen("g1", "2026-01-01")
        s.mark_gist_seen("g1", "2026-01-01")
        assert s.gist_seen("g1", "2026-01-01")
        assert not s.gist_seen("g1", "2026-01-02")
        s.close()

    def test_processed_shas_pruning(self, tmp_path):
        s = Store(str(tmp_path / "t.db"))
        s.add_processed_shas([f"sha{i}" for i in range(150)], max_keep=100)
        kept = s.load_processed_shas()
        assert len(kept) == 100
        assert kept[0] == "sha50"
        assert kept[-1] == "sha149"
        s.close()

    def test_candidate_dedupe(self, tmp_path):
        s = Store(str(tmp_path / "t.db"))
        args = dict(key="k", repo="r", file_path="f", commit_url="u",
                    author_name=None, author_email=None, source="s")
        assert s.add_candidate(key_hash="h", **args)
        assert not s.add_candidate(key_hash="h", **args)
        assert len(s.pending_candidates()) == 1
        s.close()

    def test_stale_below_threshold(self, tmp_path):
        s = Store(str(tmp_path / "t.db"))
        args = dict(key="k", repo="r", file_path="f", commit_url="u",
                    author_name=None, author_email=None, source="s")
        assert s.add_candidate(key_hash="h", **args)
        s.mark_validated("h", "below_threshold", "€0.00")
        assert len(s.stale_below_threshold(hours=48)) == 0
        s.conn.execute("UPDATE findings SET validated_at = '2020-01-01T00:00:00+00:00'"
                       " WHERE key_hash = 'h'")
        s.conn.commit()
        assert len(s.stale_below_threshold(hours=48)) == 1
        s.close()

    def test_stale_valid_unnotified(self, tmp_path):
        s = Store(str(tmp_path / "t.db"))
        args = dict(key="k", repo="r", file_path="f", commit_url="u",
                    author_name=None, author_email=None, source="s")
        assert s.add_candidate(key_hash="h", **args)
        s.mark_validated("h", "valid", "€5.00")
        assert len(s.stale_valid_unnotified(hours=1)) == 0
        s.conn.execute("UPDATE findings SET validated_at = '2020-01-01T00:00:00+00:00'"
                       " WHERE key_hash = 'h'")
        s.conn.commit()
        assert len(s.stale_valid_unnotified(hours=1)) == 1
        s.close()

    def test_sha_processed(self, tmp_path):
        s = Store(str(tmp_path / "t.db"))
        assert not s.sha_processed("abc")
        s.add_processed_shas(["abc"])
        assert s.sha_processed("abc")
        s.close()

    def test_watchlist_cap_and_force(self, tmp_path):
        s = Store(str(tmp_path / "t.db"))
        s.add_watchlist("a/b", max_count=1)
        s.add_watchlist("c/d", max_count=1)
        assert s.watchlist_due(7, 10**9) == ["a/b"]
        s.add_watchlist("e/f", max_count=1, force=True)
        assert set(s.watchlist_due(7, 10**9)) == {"a/b", "e/f"}
        s.close()

    def test_watchlist_fail_count(self, tmp_path):
        s = Store(str(tmp_path / "t.db"))
        s.add_watchlist("a/b")
        assert s.mark_watchlist_failed("a/b") == 1
        assert s.mark_watchlist_failed("a/b") == 2
        s.mark_watchlist_scanned("a/b")
        assert s.mark_watchlist_failed("a/b") == 1
        s.close()


class TestQueryBuilder:
    def test_base_queries(self):
        q = build_query_list({"queries": ["A", "B"], "max_pages_per_query": 7})
        assert q == [("A", 7), ("B", 7)]

    def test_extension_fanout(self):
        cfg = {
            "queries": ["DEEPSEEK_API_KEY"],
            "max_pages_per_query": 10,
            "extensions": ["env", "py"],
            "extension_terms": ["DEEPSEEK_API_KEY"],
            "extension_pages": 3,
        }
        q = build_query_list(cfg)
        assert q[0] == ("DEEPSEEK_API_KEY", 10)
        assert ("DEEPSEEK_API_KEY extension:env", 3) in q
        assert ("DEEPSEEK_API_KEY extension:py", 3) in q
        assert len(q) == 3

    def test_no_extensions_configured(self):
        q = build_query_list({"queries": ["A"], "max_pages_per_query": 5})
        assert q == [("A", 5)]

    def test_language_fanout(self):
        cfg = {
            "queries": ["A"],
            "max_pages_per_query": 5,
            "languages": ["Python", "Go"],
            "language_terms": ["DEEPSEEK_API_KEY"],
            "language_pages": 2,
        }
        q = build_query_list(cfg)
        assert ("DEEPSEEK_API_KEY language:Python", 2) in q
        assert ("DEEPSEEK_API_KEY language:Go", 2) in q

    def test_size_buckets(self):
        cfg = {
            "queries": ["A"],
            "max_pages_per_query": 5,
            "size_terms": ["DEEPSEEK_API_KEY"],
            "size_buckets": ["<100", "100..1000"],
            "size_pages": 4,
        }
        q = build_query_list(cfg)
        assert ("DEEPSEEK_API_KEY size:<100", 4) in q
        assert ("DEEPSEEK_API_KEY size:100..1000", 4) in q

    def test_compat_and_generic_groups(self):
        cfg = {
            "queries": ["A"],
            "max_pages_per_query": 5,
            "compat_queries": ['"OPENAI_API_KEY" "deepseek"'],
            "compat_pages": 5,
            "generic_queries": ['"sk-" filename:.env'],
            "generic_pages": 3,
        }
        q = build_query_list(cfg)
        assert ('"OPENAI_API_KEY" "deepseek"', 5) in q
        assert ('"sk-" filename:.env', 3) in q

    def test_cn_group(self):
        cfg = {
            "queries": ["A"],
            "max_pages_per_query": 5,
            "cn_queries": ['"密钥" "sk-"', '"DS_API_KEY"'],
            "cn_pages": 5,
        }
        q = build_query_list(cfg)
        assert ('"密钥" "sk-"', 5) in q
        assert ('"DS_API_KEY"', 5) in q


class TestGHArchive:
    def test_event_matches_signal_terms(self):
        event = {
            "type": "PushEvent",
            "payload": {
                "head": "abc",
                "before": "def",
                "commits": [{"sha": "abc", "message": "add DEEPSEEK_API_KEY to config"}],
            },
        }
        assert event_matches(event, ["deepseek_api_key"])

    def test_event_no_match(self):
        event = {
            "type": "PushEvent",
            "payload": {"head": "abc", "commits": [{"sha": "abc", "message": "typo fix"}]},
        }
        assert not event_matches(event, ["DEEPSEEK_API_KEY"])

    def test_non_push_ignored(self):
        event = {"type": "WatchEvent", "payload": {"DEEPSEEK_API_KEY": "x"}}
        assert not event_matches(event, ["DEEPSEEK_API_KEY"])

    def test_case_insensitive_terms(self):
        event = {
            "type": "PushEvent",
            "payload": {"head": "abc",
                        "commits": [{"sha": "abc", "message": "add DeepSeek config"}]},
        }
        assert event_matches(event, ["deepseek"])

    def test_hour_processed_once_and_monotonic(self, tmp_path):
        async def go():
            store = Store(str(tmp_path / "t.db"))
            engine = GHArchiveEngine.__new__(GHArchiveEngine)
            engine.store = store
            engine.stats = None
            engine.sem = asyncio.Semaphore(3)

            processed = []

            async def fake_download(url):
                processed.append(url)
                return []

            engine._download_and_filter = fake_download
            dt = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
            await engine._process_hour(dt)
            await engine._process_hour(dt)
            await engine._process_hour(dt - timedelta(hours=1))
            assert len(processed) == 2
            assert store.kv_get(f"gharchive_done_{dt.strftime('%Y-%m-%d-%H')}") == "1"
            store.close()

        asyncio.run(go())


class TestParallelSearchSweep:
    def test_sweep_runs_workers_concurrently(self, tmp_path):
        async def go():
            store = Store(str(tmp_path / "t.db"))
            engine = SearchEngine.__new__(SearchEngine)
            engine.queries = [(f"q{i}", 1) for i in range(8)]
            engine.tokens = TokenPool(["t1", "t2"], rate=10 / 60.0, capacity=1)
            engine.store = store
            engine.alternate_indexed_sort = False
            engine.stats = None

            active = 0
            max_active = 0

            async def fake_run_query(qi, query, pages, seen, indexed):
                nonlocal active, max_active
                active += 1
                max_active = max(max_active, active)
                await asyncio.sleep(0.05)
                active -= 1
                return True

            engine._run_query = fake_run_query
            await engine.sweep()
            assert max_active >= 2
            store.close()

        asyncio.run(go())

    def test_sweep_resumes_from_done_set(self, tmp_path):
        async def go():
            store = Store(str(tmp_path / "t.db"))
            store.kv_set("search_done", "[0]")
            engine = SearchEngine.__new__(SearchEngine)
            engine.queries = [("q0", 5), ("q1", 5), ("q2", 5)]
            engine.tokens = TokenPool(["t"], rate=1.0, capacity=1)
            engine.store = store
            engine.alternate_indexed_sort = False
            engine.stats = None

            calls = []

            async def fake_run_query(qi, query, pages, seen, indexed):
                calls.append((qi, pages))
                return True

            engine._run_query = fake_run_query
            await engine.sweep()
            assert calls == [(1, 5), (2, 5)]
            assert store.kv_get("search_done") is None
            store.close()

        asyncio.run(go())


class TestGHSearchHelpers:
    def test_days_ago_date_format(self):
        d = days_ago_date(7)
        assert re.match(r"^\d{4}-\d{2}-\d{2}$", d)

    def test_advance_cursor(self):
        assert advance_cursor("2026-09-01", ["2026-09-10T12:00:00Z"]) == "2026-09-10"
        assert advance_cursor("2026-09-01", []) == "2026-09-01"
        assert advance_cursor("2026-09-10", ["2026-09-05T00:00:00Z"]) == "2026-09-10"

    def test_advance_cursor_ignores_future_dates(self):
        assert advance_cursor("2026-09-01",
                              ["2093-01-04T22:42:08+08:00"]) == "2026-09-01"
        assert advance_cursor("2026-09-01",
                              ["2027-10-12T09:26:00+05:00",
                               "2026-09-15T00:00:00Z"]) == "2026-09-15"

    def test_sanitize_cursor(self):
        future = (datetime.now(timezone.utc) + timedelta(days=3650)).strftime("%Y-%m-%d")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert sanitize_cursor(None, 30) == days_ago_date(30)
        assert sanitize_cursor("garbage", 30) == days_ago_date(30)
        assert sanitize_cursor(future, 30) == today
        assert sanitize_cursor("2026-01-05", 30) == "2026-01-05"

    def test_prev_day(self):
        assert prev_day("2026-09-19") == "2026-09-18"
        assert prev_day("2026-03-01") == "2026-02-28"


class _FakeScanner:
    def __init__(self):
        self.calls = []

    async def scan_push(self, repo, before, head):
        self.calls.append((repo, before, head))
        return True


class TestCommitSearchEngine:
    def test_sweep_calls_scanner_and_advances_cursor(self, tmp_path):
        async def go():
            store = Store(str(tmp_path / "t.db"))
            payload = {
                "items": [
                    {"sha": "aaa1",
                     "repository": {"full_name": "owner/repo1"},
                     "commit": {"committer": {"date": "2026-09-10T10:00:00Z"}}},
                    {"sha": "bbb2",
                     "repository": {"full_name": "owner/repo2"},
                     "commit": {"committer": {"date": "2026-09-12T10:00:00Z"}}},
                ]
            }

            def handler(request):
                assert "committer-date" in request.url.params["q"]
                return httpx.Response(200, json=payload)

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = CommitSearchEngine.__new__(CommitSearchEngine)
            engine.client = client
            engine.tokens = TokenPool(["t"], rate=10.0, capacity=10)
            engine.store = store
            engine.query_list = [("deepseek key", 1)]
            engine.lookback_days = 30
            engine.interval_seconds = 900
            engine.stats = None
            fake = _FakeScanner()
            engine.scanner = fake

            await engine.sweep()
            assert fake.calls == [("owner/repo1", None, "aaa1"),
                                  ("owner/repo2", None, "bbb2")]
            assert store.kv_get("commit_search_cursor_0") == "2026-09-12"
            await client.aclose()
            store.close()

        asyncio.run(go())


class TestRepoSearchEngine:
    def test_sweep_adds_to_watchlist(self, tmp_path):
        async def go():
            store = Store(str(tmp_path / "t.db"))
            payload = {
                "items": [
                    {"full_name": "owner/repo1", "size": 100,
                     "pushed_at": "2026-09-10T10:00:00Z"},
                    {"full_name": "owner/repo2", "size": 200,
                     "pushed_at": "2026-09-12T10:00:00Z"},
                ]
            }

            def handler(request):
                assert "pushed:" in request.url.params["q"]
                return httpx.Response(200, json=payload)

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = RepoSearchEngine.__new__(RepoSearchEngine)
            engine.client = client
            engine.tokens = TokenPool(["t"], rate=10.0, capacity=10)
            engine.store = store
            engine.queries = ["deepseek"]
            engine.pages = 1
            engine.lookback_days = 90
            engine.interval_seconds = 3600
            engine.stats = None
            engine.watchlist_max = 100

            await engine.sweep()
            due = store.watchlist_due(7, 10**12)
            assert set(due) == {"owner/repo1", "owner/repo2"}
            assert store.kv_get("repo_search_cursor_0") == "2026-09-12"
            await client.aclose()
            store.close()

        asyncio.run(go())


class TestHFEngine:
    def test_fragment_key_emitted_without_raw_fetch(self, tmp_path):
        async def go():
            from scanner.hf_engine import HFEngine
            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()

            def handler(request):
                return httpx.Response(200, json={"hits": [{
                    "name": "user/demo-space", "type": "space",
                    "fileName": "app.py", "updatedAt": 123,
                    "formatted": {"fileContent": [
                        {"text": 'KEY = "sk-11112222333344445555666677778888"'}
                    ]},
                }], "estimatedTotalHits": 1})

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = HFEngine(client=client, pattern=re.compile(r"sk-[a-f0-9]{32}"),
                              store=store, candidates=q, queries=["api.deepseek.com"],
                              max_pages=1, stats=None)
            await engine.sweep()
            cand = q.get_nowait()
            assert cand["key"] == "sk-11112222333344445555666677778888"
            assert cand["source"] == "huggingface"
            assert cand["repo"] == "hf:spaces/user/demo-space"
            await client.aclose()
            store.close()

        asyncio.run(go())

    def test_raw_fetch_fallback(self, tmp_path):
        async def go():
            from scanner.hf_engine import HFEngine
            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()

            def handler(request):
                if "raw" in str(request.url):
                    return httpx.Response(
                        200, text='KEY="sk-9999aaaabbbbccccddddeeeeffff0000"')
                return httpx.Response(200, json={"hits": [{
                    "name": "user/d", "type": "dataset",
                    "fileName": "cfg.env", "updatedAt": 42,
                    "formatted": {"fileContent": [{"text": "nothing here"}]},
                }]})

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = HFEngine(client=client, pattern=re.compile(r"sk-[a-f0-9]{32}"),
                              store=store, candidates=q, queries=["q"],
                              max_pages=1, stats=None)
            await engine.sweep()
            cand = q.get_nowait()
            assert cand["key"] == "sk-9999aaaabbbbccccddddeeeeffff0000"
            await client.aclose()
            store.close()

        asyncio.run(go())


class TestStackExchangeEngine:
    def test_excerpt_key_emitted(self, tmp_path):
        async def go():
            from scanner.stackexchange_engine import StackExchangeEngine
            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()

            def handler(request):
                return httpx.Response(200, json={
                    "items": [{"title": "DeepSeek key error",
                               "body": "<code>DEEPSEEK_API_KEY=sk-77778888999900001111222233334444</code>",
                               "link": "https://stackoverflow.com/q/1",
                               "owner": {"display_name": "dev"}}],
                    "quota_remaining": 100})

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = StackExchangeEngine(
                client=client, pattern=re.compile(r"sk-[a-f0-9]{32}"),
                store=store, candidates=q, queries=["DEEPSEEK_API_KEY"],
                stats=None)
            await engine.sweep()
            cand = q.get_nowait()
            assert cand["key"] == "sk-77778888999900001111222233334444"
            assert cand["source"] == "stackexchange"
            await client.aclose()
            store.close()

        asyncio.run(go())


class TestIssueSearchEngine:
    def test_body_key_and_comment_fallback(self, tmp_path):
        async def go():
            from scanner.issue_search_engine import IssueSearchEngine
            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()

            def handler(request):
                url = str(request.url)
                if "/comments" in url:
                    return httpx.Response(200, json=[{
                        "body": "here: sk-33334444555566667777888899990000"}])
                return httpx.Response(200, json={"items": [
                    {"html_url": "https://github.com/o/r/issues/1",
                     "repository_url": "https://api.github.com/repos/o/r",
                     "title": "issue one", "body": 'key "sk-11112222333344445555666677778888"',
                     "comments": 0, "created_at": "2026-09-10T00:00:00Z",
                     "user": {"login": "alice"}},
                    {"html_url": "https://github.com/o/r/issues/2",
                     "repository_url": "https://api.github.com/repos/o/r",
                     "title": "issue two", "body": "no key here", "comments": 1,
                     "created_at": "2026-09-11T00:00:00Z",
                     "comments_url": "https://api.github.com/repos/o/r/issues/2/comments",
                     "user": {"login": "bob"}},
                ]})

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = IssueSearchEngine(
                client=client,
                search_tokens=TokenPool(["t"], rate=10.0, capacity=10),
                core_tokens=TokenPool(["t"], rate=10.0, capacity=10),
                store=store, candidates=q, pattern=re.compile(r"sk-[a-f0-9]{32}"),
                queries=["DEEPSEEK_API_KEY"], pages=1, stats=None)
            await engine.sweep()
            keys = set()
            while not q.empty():
                keys.add(q.get_nowait()["key"])
            assert keys == {"sk-11112222333344445555666677778888",
                            "sk-33334444555566667777888899990000"}
            await client.aclose()
            store.close()

        asyncio.run(go())


class TestDockerHubEngine:
    def test_config_blob_key_emitted(self, tmp_path):
        async def go():
            from scanner.dockerhub_engine import DockerHubEngine
            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()
            config = {"config": {"Env": [
                "DEEPSEEK_API_KEY=sk-aaaabbbbccccddddeeeeffff00001111"]},
                "history": [{"created_by": "RUN echo hi"}]}

            def handler(request):
                url = str(request.url)
                if "hub.docker.com" in url and "/tags" in url:
                    return httpx.Response(200, json={"results": [{"name": "latest"}]})
                if "hub.docker.com" in url:
                    return httpx.Response(200, json={"results": [
                        {"repo_name": "owner/img"}]})
                if "auth.docker.io" in url:
                    return httpx.Response(200, json={"token": "tok"})
                if "/manifests/" in url:
                    return httpx.Response(200, json={
                        "config": {"digest": "sha256:abc"}})
                if "/blobs/" in url:
                    return httpx.Response(200, json=config)
                return httpx.Response(404)

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = DockerHubEngine(
                client=client, pattern=re.compile(r"sk-[a-f0-9]{32}"),
                store=store, candidates=q, queries=["deepseek"], stats=None)
            await engine.sweep()
            cand = q.get_nowait()
            assert cand["key"] == "sk-aaaabbbbccccddddeeeeffff00001111"
            assert cand["source"] == "dockerhub"
            assert cand["file_path"] == "image config (latest)"
            await client.aclose()
            store.close()

        asyncio.run(go())


class TestKaggleNotebooks:
    def test_notebook_scan_with_basic_auth(self, tmp_path):
        async def go():
            from scanner.kaggle_engine import KaggleEngine

            key = "sk-2468ace02468ace02468ace02468ace0"

            def handler(request):
                url = str(request.url)
                if "datasets/list" in url:
                    return httpx.Response(200, json=[])
                if "kernels/list" in url:
                    assert request.headers.get("Authorization", "").startswith("Basic ")
                    return httpx.Response(200, json=[
                        {"ref": "alice/ds-demo", "versionNumber": 3}])
                if "kernels/pull" in url:
                    return httpx.Response(200, json={
                        "blob": {"source": f'KEY = "{key}"'}})
                return httpx.Response(404)

            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = KaggleEngine(
                client=client, pattern=re.compile(r"sk-[a-f0-9]{32}"),
                store=store, candidates=q, queries=["deepseek"],
                max_datasets=5, stats=None, username="u", key="k",
                notebooks=True, max_notebooks=5)
            await engine.sweep()
            cand = q.get_nowait()
            assert cand["key"] == key
            assert cand["repo"] == "kaggle:alice/ds-demo"
            assert cand["file_path"] == "notebook source"
            await client.aclose()
            store.close()

        asyncio.run(go())


class TestKaggleEngine:
    def test_sweep_downloads_and_scans(self, tmp_path):
        async def go():
            import io
            import zipfile

            from scanner.kaggle_engine import KaggleEngine

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("data/.env", "DEEPSEEK_API_KEY=sk-1234abcd5678ef901234abcd5678ef90\n")
            blob = buf.getvalue()

            def handler(request):
                if "datasets/list" in str(request.url):
                    return httpx.Response(200, json=[{
                        "refNullable": "owner/ds", "totalBytesNullable": 2048}])
                if "datasets/download" in str(request.url):
                    return httpx.Response(200, content=blob)
                return httpx.Response(404)

            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = KaggleEngine(
                client=client, pattern=re.compile(r"sk-[a-f0-9]{32}"),
                store=store, candidates=q, queries=["deepseek"],
                max_datasets=5, stats=None)
            await engine.sweep()
            cand = q.get_nowait()
            assert cand["key"] == "sk-1234abcd5678ef901234abcd5678ef90"
            assert cand["source"] == "kaggle"
            await client.aclose()
            store.close()

        asyncio.run(go())


class TestVSCodeMarketplaceEngine:
    def test_sweep_downloads_and_scans(self, tmp_path):
        async def go():
            import io
            import zipfile

            from scanner.vscode_marketplace_engine import VSCodeMarketplaceEngine

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("extension/out/config.js",
                            'const K="sk-aaaabbbbccccddddeeeeffff00001111";\n')
            blob = buf.getvalue()

            def handler(request):
                if "extensionquery" in str(request.url):
                    return httpx.Response(200, json={"results": [{
                        "extensions": [{
                            "publisher": {"publisherName": "acme"},
                            "extensionName": "deepseek-helper",
                            "versions": [{"version": "1.2.3"}],
                        }]}]})
                return httpx.Response(200, content=blob)

            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = VSCodeMarketplaceEngine(
                client=client, pattern=re.compile(r"sk-[a-f0-9]{32}"),
                store=store, candidates=q, queries=["deepseek"],
                pages=1, page_size=10, max_extensions=5, stats=None)
            await engine.sweep()
            cand = q.get_nowait()
            assert cand["key"] == "sk-aaaabbbbccccddddeeeeffff00001111"
            assert cand["source"] == "vscode"
            await client.aclose()
            store.close()

        asyncio.run(go())


class TestDiscordImport:
    def _message(self):
        return {
            "id": "111",
            "timestamp": "2026-06-30T14:15:00+00:00",
            "content": "",
            "embeds": [{
                "title": "🔮 DEEPSEEK · ✅ VALID · 💰 $6.15",
                "fields": [
                    {"name": "💰 Balance", "value": "$6.15 USD"},
                    {"name": "🔑 Key",
                     "value": "```sk-ffeeddccbbaa99887766554433221100```"},
                    {"name": "📂 Repo", "value": "LeonardoTralala/CookPlan"},
                    {"name": "🔗 Source",
                     "value": "[View commit ↗](https://github.com/LeonardoTralala/CookPlan/commit/abc)"},
                ],
                "footer": {"text": "Key Scanner • Auto-Verified"},
            }],
        }

    def test_message_text_and_context(self):
        import sys

        sys.path.insert(0, "tools")
        import discord_import as di

        msg = self._message()
        text = di.message_text(msg)
        assert "LeonardoTralala/CookPlan" in text
        ctx = di.message_context(msg)
        assert ctx["repo"] == "LeonardoTralala/CookPlan"
        assert ctx["source_url"] == \
            "https://github.com/LeonardoTralala/CookPlan/commit/abc"
        pat = re.compile(r"sk-[a-f0-9]{32}\b")
        keys = list(filters.extract_keys(text, pat))
        assert keys == ["sk-ffeeddccbbaa99887766554433221100"]

    def test_old_scraper_embed_format(self):
        import sys

        sys.path.insert(0, "tools")
        import discord_import as di

        msg = {
            "id": "222", "timestamp": "2026-07-02T20:38:00+00:00",
            "content": "",
            "embeds": [{
                "title": "DEEPSEEK · VALID · $1.97",
                "fields": [
                    {"name": "Balance", "value": "$1.97 USD"},
                    {"name": "Key", "value": "sk-00112233445566778899aabbccddeeff"},
                    {"name": "Repo", "value": "pypi:easyharmass"},
                    {"name": "Source", "value": "[View source ↗](https://pypi.org/x)"},
                ],
            }],
        }
        text = di.message_text(msg)
        pat = re.compile(r"sk-[a-f0-9]{32}\b")
        assert list(filters.extract_keys(text, pat)) == \
            ["sk-00112233445566778899aabbccddeeff"]
        ctx = di.message_context(msg)
        assert ctx["repo"] == "pypi:easyharmass"
        assert ctx["source_url"] == "https://pypi.org/x"


class TestErrorCounter:
    def test_heartbeat_logic(self):
        from scanner.ui import Stats, mark_beat, stale_engines
        s = Stats()
        mark_beat(s, "search")
        assert stale_engines(s) == []
        s.beats["old"] = time.time() - 400
        assert stale_engines(s) == ["old"]
        mark_beat(s, "slow", 7200)
        s.beats["slow"] = time.time() - 400
        assert stale_engines(s) == ["old"]

    def test_error_filter_counts(self):
        import logging

        from scanner.ui import Stats
        from main import ErrorCounter

        stats = Stats()
        counter = ErrorCounter(stats)
        logger = logging.getLogger("test.errcount")
        logger.addFilter(counter)
        logger.setLevel(logging.DEBUG)
        record = logger.makeRecord("test.errcount", logging.ERROR, "f", 1,
                                   "boom", None, None)
        assert counter.filter(record) is True
        assert stats.errors == 1
        record2 = logger.makeRecord("test.errcount", logging.INFO, "f", 1,
                                    "ok", None, None)
        assert counter.filter(record2) is True
        assert stats.errors == 1


class TestDiffScanner:
    COMPARE_DIFF = (
        "diff --git a/.env b/.env\n"
        "--- a/.env\n"
        "+++ b/.env\n"
        "+DEEPSEEK_API_KEY=sk-11112222333344445555666677778888\n"
    )
    HEAD_PATCH = (
        "From abc123 Mon Sep 17 00:00:00 2001\n"
        "From: Alice <alice@example.com>\n"
        "\n"
        + COMPARE_DIFF
    )

    def _make_client(self, compare_text, patch_text):
        calls = []

        def handler(request):
            calls.append(str(request.url))
            if "/compare/" in str(request.url):
                return httpx.Response(200, text=compare_text)
            return httpx.Response(200, text=patch_text)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return client, calls

    def test_scan_push_finds_key_and_author(self, tmp_path):
        async def go():
            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()
            client, calls = self._make_client(self.COMPARE_DIFF, self.HEAD_PATCH)
            scanner = DiffScanner(
                client=client,
                pattern=re.compile(r"sk-[a-f0-9]{32}"),
                store=store,
                candidates=q,
                patch_bucket=TokenBucket(rate=100, capacity=100),
                source="events",
            )
            await scanner.scan_push("owner/repo", "before-sha", "head-sha")
            assert len(calls) == 2
            assert any("/compare/" in c for c in calls)
            assert any(c.endswith("head-sha.patch") for c in calls)
            cand = await q.get()
            assert cand["key"] == "sk-11112222333344445555666677778888"
            assert cand["repo"] == "owner/repo"
            assert cand["file_path"] == ".env"
            assert cand["author_email"] == "alice@example.com"
            assert cand["source"] == "events"
            await client.aclose()
            store.close()

        asyncio.run(go())

    def test_scan_push_no_match_skips_author_fetch(self, tmp_path):
        async def go():
            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()
            client, calls = self._make_client(
                "diff --git a/x b/x\n--- a/x\n+++ b/x\n+nothing interesting\n",
                self.HEAD_PATCH,
            )
            scanner = DiffScanner(
                client=client,
                pattern=re.compile(r"sk-[a-f0-9]{32}"),
                store=store,
                candidates=q,
                patch_bucket=TokenBucket(rate=100, capacity=100),
                source="events",
            )
            await scanner.scan_push("owner/repo", "before-sha", "head-sha")
            assert len(calls) == 1
            await client.aclose()
            store.close()

        asyncio.run(go())

    def test_scan_push_dedupes_processed_sha(self, tmp_path):
        async def go():
            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()
            client, calls = self._make_client(self.COMPARE_DIFF, self.HEAD_PATCH)
            scanner = DiffScanner(
                client=client,
                pattern=re.compile(r"sk-[a-f0-9]{32}"),
                store=store,
                candidates=q,
                patch_bucket=TokenBucket(rate=100, capacity=100),
                source="events",
            )
            assert await scanner.scan_push("owner/repo", "b", "h") is True
            n_calls = len(calls)
            assert await scanner.scan_push("owner/repo", "b", "h") is True
            assert len(calls) == n_calls
            await client.aclose()
            store.close()

        asyncio.run(go())

    def test_scan_push_failed_fetch_not_marked(self, tmp_path):
        async def go():
            store = Store(str(tmp_path / "t.db"))

            def handler(request):
                return httpx.Response(500, text="boom")

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            scanner = DiffScanner(
                client=client,
                pattern=re.compile(r"sk-[a-f0-9]{32}"),
                store=store,
                candidates=asyncio.Queue(),
                patch_bucket=TokenBucket(rate=100, capacity=100),
                source="events",
            )
            assert await scanner.scan_push("owner/repo", "b", "h") is False
            assert not store.sha_processed("h")
            await client.aclose()
            store.close()

        asyncio.run(go())


class TestTokenPool:
    def test_pool_rotation(self):
        pool = TokenPool(["tok1", "tok2"], rate=0.5, capacity=1)
        assert pool.pairs[0][1].try_acquire()
        assert pool.pairs[0][1].try_acquire() is False
        assert pool.pairs[1][1].try_acquire()

    def test_async_acquire_waits(self):
        import time

        async def go():
            pool = TokenPool(["tok"], rate=2.0, capacity=1)
            assert await pool.acquire() == "tok"
            t0 = time.monotonic()
            await asyncio.wait_for(pool.acquire(), timeout=5)
            assert time.monotonic() - t0 >= 0.4

        asyncio.run(go())


class TestEventsPatchParsing:
    def test_parse_from(self):
        text = (
            "From 1234abc Mon Sep 17 00:00:00 2001\n"
            "From: John Doe <john@example.com>\n"
            "Subject: [PATCH] x\n"
        )
        name, email = parse_from(text)
        assert name == "John Doe"
        assert email == "john@example.com"

    def test_parse_from_missing(self):
        name, email = parse_from("From 1234abc Mon Sep 17 00:00:00 2001\n")
        assert name is None and email is None

    def test_iter_added_lines_tracks_files(self):
        diff = (
            "diff --git a/app/.env b/app/.env\n"
            "--- a/app/.env\n"
            "+++ b/app/.env\n"
            "@@ -1,2 +1,3 @@\n"
            "-OLD\n"
            "+DEEPSEEK_API_KEY=sk-11112222333344445555666677778888\n"
            "diff --git a/src/main.py b/src/main.py\n"
            "--- a/src/main.py\n"
            "+++ b/src/main.py\n"
            "+const KEY = 'sk-9999aaaabbbbccccddddeeeeffff0000'\n"
        )
        found = list(iter_added_lines(diff))
        assert ("app/.env", "DEEPSEEK_API_KEY=sk-11112222333344445555666677778888") in found
        assert ("src/main.py", "const KEY = 'sk-9999aaaabbbbccccddddeeeeffff0000'") in found
        assert not any(l.startswith("-OLD") or l.startswith("+++") or l.startswith("---")
                       for _, l in found)


class TestFilters:
    def test_placeholder_all_same(self):
        assert filters.is_placeholder("sk-00000000000000000000000000000000")
        assert filters.is_placeholder("sk-ffffffffffffffffffffffffffffffff")

    def test_placeholder_low_entropy(self):
        assert filters.is_placeholder("sk-abababababababababababababababab")
        assert filters.is_placeholder("sk-abcabcabcabcabcabcabcabcabcabcab")

    def test_real_key_passes(self):
        assert not filters.is_placeholder("sk-0123456789abcdef0123456789abcdef")

    def test_entropy_math(self):
        assert filters.shannon_entropy("") == 0.0
        assert filters.shannon_entropy("aaaa") == 0.0
        assert abs(filters.shannon_entropy("ab") - 1.0) < 1e-9
        assert filters.shannon_entropy("0123456789abcdef") == 4.0

    def test_extract_keys_plaintext_and_base64(self):
        import base64

        pat = re.compile(r"sk-[a-f0-9]{32}\b")
        plain = "sk-11112222333344445555666677778888"
        assert list(filters.extract_keys(f"KEY={plain}", pat)) == [plain]

        key = "sk-9999aaaabbbbccccddddeeeeffff0000"
        b64 = base64.b64encode(key.encode()).decode()
        assert list(filters.extract_keys(f'const K = atob("{b64}");', pat)) == [key]

        both = f"line with {plain} and also atob('{b64}')"
        assert list(filters.extract_keys(both, pat)) == [plain, key]

    def test_extract_keys_ignores_non_key_base64(self):
        import base64

        pat = re.compile(r"sk-[a-f0-9]{32}\b")
        b64 = base64.b64encode(b"just some regular data, nothing secret!!").decode()
        assert list(filters.extract_keys(f'data = "{b64}"', pat)) == []

    def test_extract_keys_obfuscations(self):
        pat = re.compile(r"sk-[a-f0-9]{32}\b")
        key = "sk-1234abcd5678ef901234abcd5678ef90"
        concat = '"sk-" + "1234abcd5678ef901234abcd5678ef90"'
        assert key in list(filters.extract_keys(concat, pat))
        hexesc = '"' + "".join(f"\\x{b:02x}" for b in key.encode()) + '"'
        assert key in list(filters.extract_keys(hexesc, pat))
        hexstr = key.encode().hex()
        assert key in list(filters.extract_keys(f"token={hexstr}", pat))
        pct = "".join(f"%{b:02x}" for b in key.encode())
        assert key in list(filters.extract_keys(f"k={pct}", pat))
        rev = key[::-1]
        assert key in list(filters.extract_keys(f"x={rev}", pat))

    def test_denylist(self):
        deny = frozenset({"sk-0123456789abcdef0123456789abcdef"})
        assert filters.is_placeholder("sk-0123456789abcdef0123456789abcdef", deny)
        assert not filters.is_placeholder("sk-a3b4c5d6e7f8091a2b3c4d5e6f708192", deny)


class TestValidator:
    def test_parse_valid(self):
        ok, balances = validator.Validator._parse({
            "is_available": True,
            "balance_infos": [
                {"currency": "USD", "total_balance": "0.97"},
                {"currency": "CNY", "total_balance": "2.0"},
            ],
        })
        assert ok and balances == [(0.97, "USD"), (2.0, "CNY")]

    def test_parse_unavailable_still_authenticated(self):
        ok, balances = validator.Validator._parse({
            "is_available": False,
            "balance_infos": [{"currency": "USD", "total_balance": "5.0"}],
        })
        assert ok and balances == [(5.0, "USD")]

    def test_parse_missing_currency(self):
        ok, balances = validator.Validator._parse({
            "is_available": True,
            "balance_infos": [{"total_balance": "5.0"}],
        })
        assert ok and balances == []

    def test_http_403_with_real_key_restricted(self):
        async def go():
            real = "sk-" + "a" * 32

            def handler(request):
                auth = request.headers.get("Authorization", "")
                if real in auth:
                    return httpx.Response(403, text="restricted")
                return httpx.Response(401, text="invalid dummy")

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            v = validator.Validator(client, concurrency=1)
            result, balances = await v.check(real)
            assert result == "valid"
            assert balances == []
            await client.aclose()

        asyncio.run(go())

    def test_http_403_ip_block_defers(self):
        async def go():
            def handler(request):
                return httpx.Response(403, text="blocked")

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            v = validator.Validator(client, concurrency=1)
            result, balances = await v.check("sk-" + "b" * 32)
            assert result == "retry"
            await client.aclose()

        asyncio.run(go())


class TestEventsMultiPage:
    def test_poll_fetches_all_pages(self, tmp_path):
        async def go():
            from scanner.events_engine import EventsEngine

            def event(sha):
                return {"type": "PushEvent",
                        "repo": {"name": "owner/repo"},
                        "payload": {"head": sha, "before": "b"}}

            def handler(request):
                page = int(request.url.params.get("page", 1))
                if page == 1:
                    items = [event(f"a{i:03d}") for i in range(100)]
                else:
                    items = [event("bbb")]
                return httpx.Response(200, json=items,
                                      headers={"ETag": f'"etag{page}"'})

            store = Store(str(tmp_path / "t.db"))
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = EventsEngine.__new__(EventsEngine)
            engine.client = client
            engine.tokens = TokenPool(["t"], rate=10.0, capacity=10)
            engine.store = store
            engine.pages = 2
            engine.poll_interval = 30
            engine.max_shas = 1000
            engine.stats = None
            engine.processed = {}
            fake = _FakeScanner()
            engine.scanner = fake

            await engine._poll()
            heads = [c[2] for c in fake.calls]
            assert len(heads) == 101
            assert heads[0] == "a000"
            assert heads[-1] == "bbb"
            assert store.kv_get("events_etag") == '"etag1"'
            assert store.kv_get("events_etag_p2") == '"etag2"'
            await client.aclose()
            store.close()

        asyncio.run(go())


class TestOpenVSXEngine:
    def test_sweep_downloads_and_scans_vsix(self, tmp_path):
        async def go():
            import io
            import zipfile

            from scanner.openvsx_engine import OpenVSXEngine

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("extension/dist/config.js",
                            'const KEY = "sk-55556666777788889999000011112222";\n')
            blob = buf.getvalue()

            def handler(request):
                if "/api/-/search" in str(request.url):
                    return httpx.Response(200, json={"extensions": [{
                        "namespace": "acme", "name": "deepseek-helper",
                        "version": "1.0.0",
                        "files": {"download": "https://open-vsx.org/dl/ext.vsix"},
                    }]})
                return httpx.Response(200, content=blob)

            store = Store(str(tmp_path / "t.db"))
            q = asyncio.Queue()
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            engine = OpenVSXEngine(
                client=client, pattern=re.compile(r"sk-[a-f0-9]{32}"),
                store=store, candidates=q, queries=["deepseek"],
                max_extensions=5, stats=None)
            await engine.sweep()
            cand = q.get_nowait()
            assert cand["key"] == "sk-55556666777788889999000011112222"
            assert cand["source"] == "openvsx"
            await client.aclose()
            store.close()

        asyncio.run(go())

    def test_http_401_invalid(self):
        async def go():
            def handler(request):
                return httpx.Response(401, text="bad key")

            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            v = validator.Validator(client, concurrency=1)
            result, balances = await v.check("sk-" + "a" * 32)
            assert result == "invalid"
            await client.aclose()

        asyncio.run(go())


class TestFx:
    def test_fallback_conversion(self):
        conv = CurrencyConverter.__new__(CurrencyConverter)
        conv.rates = dict(FALLBACK_RATES)
        assert abs(conv.to_eur(1.0, "USD") - 0.92) < 1e-9
        assert conv.to_eur(1.0, "EUR") == 1.0
        assert abs(conv.to_eur(100.0, "CNY") - 100 / 7.1 * 0.92) < 1e-9

    def test_unknown_currency_returns_none(self):
        conv = CurrencyConverter.__new__(CurrencyConverter)
        conv.rates = dict(FALLBACK_RATES)
        assert conv.to_eur(1.0, "JPY") is None

    def test_no_api_url_skips_fetch(self):
        conv = CurrencyConverter.__new__(CurrencyConverter)
        conv.api_url = ""
        conv.using_fallback = True
        asyncio.run(conv.ensure())
        assert conv.using_fallback


class TestNotifier:
    def test_embed_single(self):
        n = Notifier.__new__(Notifier)
        embeds = n.build_embeds([{
            "key": "sk-0123456789abcdef0123456789abcdef",
            "balance_eur": "€12.93",
            "repo": "owner/repo",
            "file_path": "app/.env",
            "author_email": "a@b.c",
            "commit_url": "https://github.com/owner/repo/commit/x",
        }])
        assert len(embeds) == 1
        embed = embeds[0]
        assert "€12.93" in embed["title"]
        assert embed["fields"][0]["value"] == "€12.93 EUR"
        assert any(f["name"] == "🔑 Key" for f in embed["fields"])
        assert any(f["name"] == "📂 Repo" for f in embed["fields"])
        assert any(f["name"] == "📄 File" for f in embed["fields"])
        assert any(f["name"] == "👤 Author" for f in embed["fields"])
        assert embed["footer"]["text"] == "Key Scanner • Auto-Verified"

    def test_embed_grouped(self):
        n = Notifier.__new__(Notifier)
        embeds = n.build_embeds([
            {"key": "sk-aaaa0000111122223333444455556666", "balance_eur": "€5.00",
             "repo": "owner/repo", "commit_url": None},
            {"key": "sk-bbbb0000111122223333444455556666", "balance_eur": "€5.00",
             "repo": "owner/repo", "commit_url": None},
        ])
        assert len(embeds) == 1
        embed = embeds[0]
        keys_field = next(f for f in embed["fields"] if f["name"] == "🔑 Key")
        assert "sk-aaaa0000111122223333444455556666" in keys_field["value"]
        assert "sk-bbbb0000111122223333444455556666" in keys_field["value"]
        assert "2 keys" in embed["title"]
        assert not any(f["name"] == "📄 File" for f in embed["fields"])

    def test_embed_chunking_caps_field_size(self):
        n = Notifier.__new__(Notifier)
        items = [{"key": "sk-" + f"{i:032x}", "balance_eur": "€5.00",
                  "repo": "owner/repo", "commit_url": None} for i in range(60)]
        embeds = n.build_embeds(items)
        assert len(embeds) > 1
        for embed in embeds:
            keys_field = next(f for f in embed["fields"] if f["name"] == "🔑 Key")
            assert len(keys_field["value"]) <= 1024


class FakeStore:
    def __init__(self):
        self.statuses = {}
        self.notified = []

    def mark_validated(self, h, status, balance):
        self.statuses[h] = (status, balance)

    def mark_notified(self, h):
        self.notified.append(h)
        prev = self.statuses.get(h)
        self.statuses[h] = ("notified", prev[1] if prev else None)


class FakeNotifier:
    def __init__(self, ok=True):
        self.calls = []
        self.ok = ok

    async def notify_many(self, items):
        self.calls.append(items)
        return self.ok


class FakeValidator:
    def __init__(self, results):
        self.results = list(results)

    async def check(self, key):
        return self.results.pop(0)


class FakeFx:
    async def ensure(self):
        pass

    def to_eur(self, amount, cur):
        rate = {"USD": 0.87, "CNY": 0.122, "EUR": 1.0}.get(cur)
        return None if rate is None else rate * amount


def make_cand(i):
    return {"key_hash": f"h{i}", "key": f"sk-test{i}", "repo": f"r{i % 3}",
            "commit_url": None, "file_path": None, "author_name": None,
            "author_email": None, "source": "test"}


async def run_validation(results, notify_all_valid=False, min_balance=3.0):
    import main as M
    from scanner.ui import Stats

    q = asyncio.Queue()
    nq = asyncio.Queue()
    for i in range(len(results)):
        q.put_nowait(make_cand(i))
    store, notifier, stats = FakeStore(), FakeNotifier(), Stats()
    task = asyncio.create_task(
        M.validation_loop(q, asyncio.Queue(), FakeValidator(results), store, stats,
                          FakeFx(), min_balance, nq, set(), notify_all_valid))
    await q.join()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return store, stats, nq


class TestPkgScan:
    def test_zip_scan(self, tmp_path):
        import zipfile

        p = tmp_path / "x.zip"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("pkg/config.py",
                        'KEY = "sk-11112222333344445555666677778888"\n')
            zf.writestr("pkg/bin", b"\x00\x01\x02binary")
        matches = scan_archive(str(p), re.compile(r"sk-[a-f0-9]{32}"))
        assert matches == [("pkg/config.py", "sk-11112222333344445555666677778888")]

    def test_tar_scan(self, tmp_path):
        import tarfile

        p = tmp_path / "x.tgz"
        with tarfile.open(p, "w:gz") as tf:
            import io

            data = b"DEEPSEEK_API_KEY=sk-9999aaaabbbbccccddddeeeeffff0000\n"
            info = tarfile.TarInfo("cfg/.env")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        matches = scan_archive(str(p), re.compile(r"sk-[a-f0-9]{32}"))
        assert matches == [("cfg/.env", "sk-9999aaaabbbbccccddddeeeeffff0000")]

    def test_placeholder_skipped(self, tmp_path):
        import zipfile

        p = tmp_path / "x.zip"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("f", "sk-00000000000000000000000000000000\n")
        assert scan_archive(str(p), re.compile(r"sk-[a-f0-9]{32}")) == []


def test_validation_threshold_pipeline():
    store, stats, nq = asyncio.run(run_validation([
        ("valid", [(10.0, "USD")]),
        ("valid", [(2.0, "USD")]),
        ("valid", [(-14.83, "CNY")]),
        ("invalid", []),
        ("retry", []),
        ("valid", [(5.0, "JPY")]),
    ]))
    assert stats.valid == 1
    assert stats.invalid == 1
    assert stats.skipped == 3
    assert store.statuses["h0"][0] == "valid"
    assert store.statuses["h1"][0] == "below_threshold"
    assert store.statuses["h2"][0] == "below_threshold"
    assert store.statuses["h3"][0] == "invalid"
    assert "h4" not in store.statuses
    assert store.statuses["h5"][0] == "below_threshold"
    assert nq.qsize() == 1


def test_notify_all_valid_notifies_depleted():
    store, stats, nq = asyncio.run(run_validation([
        ("valid", [(2.0, "USD")]),
        ("invalid", []),
    ], notify_all_valid=True))
    assert stats.valid == 1
    assert stats.invalid == 1
    assert nq.qsize() == 1
    item = asyncio.run(asyncio.wait_for(nq.get(), timeout=1))
    assert item["key_hash"] == "h0"
    assert item["balance_eur"] == "€1.74"


def test_notify_positive_balance_only():
    store, stats, nq = asyncio.run(run_validation([
        ("valid", [(0.01, "USD")]),
        ("valid", [(0.0, "USD")]),
        ("valid", [(-0.01, "USD")]),
        ("valid", []),
    ], min_balance=0.0))
    assert stats.valid == 1
    assert stats.skipped == 3
    assert nq.qsize() == 1
    item = asyncio.run(asyncio.wait_for(nq.get(), timeout=1))
    assert item["key_hash"] == "h0"


async def run_notify(items):
    import main as M
    from scanner.ui import Stats

    q = asyncio.Queue()
    for it in items:
        q.put_nowait(it)
    store, notifier, stats = FakeStore(), FakeNotifier(), Stats()
    task = asyncio.create_task(M.notify_worker(q, notifier, store, stats))
    await q.put(None)
    await task
    return store, notifier, stats


def test_notify_grouping_by_repo():
    items = [
        {**make_cand(0), "repo": "A", "balance_eur": "€5.00"},
        {**make_cand(1), "repo": "A", "balance_eur": "€6.00"},
        {**make_cand(2), "repo": "B", "balance_eur": "€7.00"},
    ]
    store, notifier, stats = asyncio.run(run_notify(items))
    assert len(notifier.calls) == 2
    by_repo = {call[0]["repo"]: len(call) for call in notifier.calls}
    assert by_repo == {"A": 2, "B": 1}
    assert stats.notified == 3
    assert set(store.notified) == {"h0", "h1", "h2"}


class TestCloneEngine:
    def _make_repo(self, path):
        import subprocess

        def git(*args):
            subprocess.run(["git", "-C", str(path)] + list(args),
                           check=True, capture_output=True)

        path.mkdir()
        subprocess.run(["git", "init", "-q", str(path)], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(path), "config", "user.email", "t@t.t"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(path), "config", "user.name", "T"],
                       check=True, capture_output=True)
        (path / "leak.txt").write_text(
            "DEEPSEEK_API_KEY=sk-11112222333344445555666677778888\n")
        git("add", "leak.txt")
        git("commit", "-q", "-m", "add key")
        (path / "leak.txt").write_text("nothing here\n")
        git("add", "leak.txt")
        git("commit", "-q", "-m", "remove key")
        return path

    def test_git_grep_finds_removed_key(self, tmp_path):
        repo = self._make_repo(tmp_path / "repo")
        engine = CloneEngine(store=object(), pattern=re.compile(r"sk-[a-f0-9]{32}"),
                             candidates=asyncio.Queue())
        matches = engine._git_grep(str(repo))
        keys = {k for _, k in matches}
        assert "sk-11112222333344445555666677778888" in keys

    def test_find_commit_returns_author(self, tmp_path):
        repo = self._make_repo(tmp_path / "repo")
        engine = CloneEngine(store=object(), pattern=re.compile(r"sk-[a-f0-9]{32}"),
                             candidates=asyncio.Queue())
        sha, name, email = engine._find_commit(
            str(repo), "sk-11112222333344445555666677778888")
        assert sha is not None
        assert name == "T"
        assert email == "t@t.t"

    def test_git_grep_finds_base64_key(self, tmp_path):
        import base64
        import subprocess

        repo = self._make_repo(tmp_path / "repo")
        key = "sk-77778888999900001111222233334444"
        b64 = base64.b64encode(key.encode()).decode()
        (repo / "app.js").write_text(f'const K = atob("{b64}");\n')
        subprocess.run(["git", "-C", str(repo), "add", "app.js"], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "obfuscated"],
                       check=True, capture_output=True)
        engine = CloneEngine(store=object(), pattern=re.compile(r"sk-[a-f0-9]{32}"),
                             candidates=asyncio.Queue())
        matches = engine._git_grep(str(repo))
        keys = {k for _, k in matches}
        assert "sk-77778888999900001111222233334444" in keys

    def test_placeholder_keys_skipped(self, tmp_path):
        repo = self._make_repo(tmp_path / "repo")
        (repo / "fake.txt").write_text("sk-00000000000000000000000000000000\n")
        import subprocess

        subprocess.run(["git", "-C", str(repo), "add", "fake.txt"], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "fake"],
                       check=True, capture_output=True)
        engine = CloneEngine(store=object(), pattern=re.compile(r"sk-[a-f0-9]{32}"),
                             candidates=asyncio.Queue())
        matches = engine._git_grep(str(repo))
        keys = {k for _, k in matches}
        assert "sk-00000000000000000000000000000000" not in keys
        assert "sk-11112222333344445555666677778888" in keys
