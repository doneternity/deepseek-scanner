import logging
import time
from collections import deque

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class Stats:
    def __init__(self):
        self.candidates = 0
        self.valid = 0
        self.notified = 0
        self.invalid = 0
        self.skipped = 0
        self.search_query = "idle"
        self.search_page = 0
        self.search_results = 0
        self.search_rate = "?"
        self.events_seen = 0
        self.events_new = 0
        self.core_rate = "?"
        self.gists_seen = 0
        self.gists_new = 0
        self.grep_hits = 0
        self.clone_repos = 0
        self.gharchive_files = 0
        self.urlscan_hits = 0
        self.gitlab_hits = 0
        self.gitlab_events = 0
        self.npm_pkgs = 0
        self.pypi_pkgs = 0
        self.commit_hits = 0
        self.repo_hits = 0
        self.issue_hits = 0
        self.hf_hits = 0
        self.stack_hits = 0
        self.docker_images = 0
        self.kaggle_sets = 0
        self.kaggle_nbs = 0
        self.openvsx_ext = 0
        self.vscode_ext = 0
        self.started_at = time.time()
        self.errors = 0
        self.beats: dict[str, float] = {}
        self.intervals: dict[str, float] = {}
        self.recent = deque(maxlen=8)
        self.logs = deque(maxlen=9)


def mark_beat(stats: Stats, name: str, interval: float | None = None):
    stats.beats[name] = time.time()
    if interval:
        stats.intervals[name] = interval


def stale_engines(stats: Stats, default_threshold: float = 300.0) -> list[str]:
    now = time.time()
    stale = []
    for name, t in stats.beats.items():
        interval = stats.intervals.get(name, 0.0)
        threshold = max(default_threshold, interval * 2.5)
        if now - t > threshold:
            stale.append(name)
    return stale


class StatsLogHandler(logging.Handler):
    def __init__(self, stats: Stats, level=logging.DEBUG):
        super().__init__(level)
        self.stats = stats

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            line = msg.split(": ", 3)
            short = f"[{record.levelname[0]}] {line[-1]}" if len(line) > 3 else msg
            self.stats.logs.append(short)
        except Exception:
            pass


def _style(status: str) -> str:
    if status == "notified":
        return "bold green"
    if status == "valid":
        return "green"
    return "red"


def render(stats: Stats) -> Group:
    header = Text()
    header.append("🔮 ", style="bold magenta")
    header.append("DeepSeek Key Scanner", style="bold white on purple")
    uptime = max(0, int(time.time() - stats.started_at))
    hours, rem = divmod(uptime, 3600)
    minutes, seconds = divmod(rem, 60)
    header.append(f"  up {hours}h{minutes:02d}m{seconds:02d}s",
                  style="bold white")

    stat_line = Text()
    stat_line.append(f"Candidates {stats.candidates}   ", style="cyan")
    stat_line.append(f"✓ Valid {stats.valid}   ", style="green")
    stat_line.append(f"🔔 Notified {stats.notified}   ", style="bold green")
    stat_line.append(f"✗ Invalid {stats.invalid}   ", style="red")
    stat_line.append(f"– Skipped {stats.skipped}   ", style="yellow")
    if stats.errors:
        stat_line.append(f"⚠ Errors {stats.errors}", style="bold red")

    engines = Table(show_header=False, box=None, padding=(0, 1))
    engines.add_row(
        Text("Search", style="bold purple"),
        Text(f"{stats.search_query}  page {stats.search_page}  "
             f"({stats.search_results} results)  search-API {stats.search_rate}", style="white"),
    )
    engines.add_row(
        Text("Events", style="bold purple"),
        Text(f"seen {stats.events_seen}  new commits {stats.events_new}  "
             f"core-API {stats.core_rate}", style="white"),
    )
    engines.add_row(
        Text("Gists", style="bold purple"),
        Text(f"seen {stats.gists_seen}  new {stats.gists_new}", style="white"),
    )
    engines.add_row(
        Text("Grep.app", style="bold purple"),
        Text(f"hits {stats.grep_hits}", style="white"),
    )
    engines.add_row(
        Text("History", style="bold purple"),
        Text(f"repos cloned {stats.clone_repos}", style="white"),
    )
    engines.add_row(
        Text("Archive", style="bold purple"),
        Text(f"files {stats.gharchive_files}", style="white"),
    )
    engines.add_row(
        Text("Web/Other", style="bold purple"),
        Text(f"urlscan {stats.urlscan_hits}  gitlab {stats.gitlab_hits}"
             f"  events {stats.gitlab_events}", style="white"),
    )
    engines.add_row(
        Text("Registries", style="bold purple"),
        Text(f"npm {stats.npm_pkgs}  pypi {stats.pypi_pkgs}", style="white"),
    )
    engines.add_row(
        Text("GH API", style="bold purple"),
        Text(f"commit-search {stats.commit_hits}  repo-search {stats.repo_hits}"
             f"  issues {stats.issue_hits}", style="white"),
    )
    engines.add_row(
        Text("Other", style="bold purple"),
        Text(f"hf {stats.hf_hits}  stackoverflow {stats.stack_hits}"
             f"  docker {stats.docker_images}  kaggle {stats.kaggle_sets}ds/{stats.kaggle_nbs}nb"
             f"  openvsx {stats.openvsx_ext}  vscode {stats.vscode_ext}",
             style="white"),
    )
    stale = stale_engines(stats)
    if stale:
        engines.add_row(
            Text("⚠ Stale", style="bold red"),
            Text(", ".join(sorted(stale)) + " (no activity >5m)", style="bold red"),
        )

    findings = Table(show_header=True, box=None, padding=(0, 1))
    findings.add_column("Repo", style="cyan", no_wrap=True)
    findings.add_column("Balance", style="yellow", justify="right")
    findings.add_column("Status", justify="center")
    if stats.recent:
        for repo, balance, status in stats.recent:
            findings.add_row(repo, balance, Text(status, style=_style(status)))
    else:
        findings.add_row("—", "—", "—")

    log_text = Text()
    for entry in stats.logs:
        log_text.append(entry + "\n", style="dim")
    if not stats.logs:
        log_text = Text("waiting for log output…", style="dim")

    return Group(
        Panel(header, border_style="magenta"),
        Panel(Group(stat_line, "", engines), title="Status", border_style="purple"),
        Panel(findings, title="Recent Findings", border_style="purple"),
        Panel(log_text, title="Log", border_style="purple"),
    )
