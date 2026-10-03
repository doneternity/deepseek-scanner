import sqlite3
import threading
from datetime import datetime, timezone


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str = "findings.db"):
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_hash TEXT UNIQUE NOT NULL,
                    key TEXT NOT NULL,
                    repo TEXT NOT NULL,
                    file_path TEXT,
                    commit_url TEXT,
                    author_name TEXT,
                    author_email TEXT,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new',
                    balance TEXT,
                    found_at TEXT NOT NULL,
                    notified_at TEXT,
                    validated_at TEXT
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS kv (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS seen_files (
                    repo TEXT NOT NULL,
                    path TEXT NOT NULL,
                    sha TEXT NOT NULL,
                    PRIMARY KEY (repo, path)
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS seen_gists (
                    gist_id TEXT PRIMARY KEY,
                    updated_at TEXT NOT NULL
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS seen_shas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha TEXT UNIQUE NOT NULL
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS watchlist (
                    repo TEXT PRIMARY KEY,
                    size_kb INTEGER,
                    added_at TEXT NOT NULL,
                    last_scanned TEXT,
                    fail_count INTEGER NOT NULL DEFAULT 0
                )
            """)
        cols = {row[1] for row in self.conn.execute("PRAGMA table_info(findings)")}
        if "validated_at" not in cols:
            with self.conn:
                self.conn.execute("ALTER TABLE findings ADD COLUMN validated_at TEXT")
        wcols = {row[1] for row in self.conn.execute("PRAGMA table_info(watchlist)")}
        if "fail_count" not in wcols:
            with self.conn:
                self.conn.execute("ALTER TABLE watchlist ADD COLUMN fail_count INTEGER"
                                  " NOT NULL DEFAULT 0")

    def add_candidate(self, *, key_hash, key, repo, file_path, commit_url,
                      author_name, author_email, source) -> bool:
        with self._lock:
            try:
                self.conn.execute(
                    "INSERT INTO findings (key_hash, key, repo, file_path, commit_url,"
                    " author_name, author_email, source, status, found_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)",
                    (key_hash, key, repo, file_path, commit_url,
                     author_name, author_email, source, utcnow()),
                )
                self.conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def mark_validated(self, key_hash: str, status: str, balance: str | None):
        with self._lock:
            self.conn.execute(
                "UPDATE findings SET status = ?, balance = ?, validated_at = ?"
                " WHERE key_hash = ?",
                (status, balance, utcnow(), key_hash),
            )
            self.conn.commit()

    def stale_below_threshold(self, hours: int, limit: int = 25):
        cutoff = datetime.now(timezone.utc).timestamp() - hours * 3600
        cutoff_str = datetime.fromtimestamp(cutoff, timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, key_hash, key, repo, file_path, commit_url,"
                " author_name, author_email, source FROM findings"
                " WHERE status = 'below_threshold'"
                " AND (validated_at IS NULL OR validated_at < ?)"
                " ORDER BY validated_at LIMIT ?",
                (cutoff_str, limit),
            ).fetchall()
        return [dict(zip(("id", "key_hash", "key", "repo", "file_path", "commit_url",
                          "author_name", "author_email", "source"), row)) for row in rows]

    def stale_valid_unnotified(self, hours: int, limit: int = 25):
        cutoff = datetime.now(timezone.utc).timestamp() - hours * 3600
        cutoff_str = datetime.fromtimestamp(cutoff, timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, key_hash, key, repo, file_path, commit_url,"
                " author_name, author_email, source FROM findings"
                " WHERE status = 'valid'"
                " AND (validated_at IS NULL OR validated_at < ?)"
                " ORDER BY validated_at LIMIT ?",
                (cutoff_str, limit),
            ).fetchall()
        return [dict(zip(("id", "key_hash", "key", "repo", "file_path", "commit_url",
                          "author_name", "author_email", "source"), row)) for row in rows]

    def sha_processed(self, sha: str) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM seen_shas WHERE sha = ?", (sha,)
            ).fetchone()
        return row is not None

    def mark_notified(self, key_hash: str):
        with self._lock:
            self.conn.execute(
                "UPDATE findings SET status = 'notified', notified_at = ? WHERE key_hash = ?",
                (utcnow(), key_hash),
            )
            self.conn.commit()

    def pending_candidates(self, limit: int = 100):
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, key_hash, key, repo, file_path, commit_url,"
                " author_name, author_email, source FROM findings"
                " WHERE status = 'new' ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(zip(("id", "key_hash", "key", "repo", "file_path", "commit_url",
                          "author_name", "author_email", "source"), row)) for row in rows]

    def kv_get(self, key: str) -> str | None:
        with self._lock:
            row = self.conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def kv_set(self, key: str, value: str):
        with self._lock:
            self.conn.execute(
                "INSERT INTO kv (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self.conn.commit()

    def kv_del(self, key: str):
        with self._lock:
            self.conn.execute("DELETE FROM kv WHERE key = ?", (key,))
            self.conn.commit()

    def file_seen(self, repo: str, path: str, sha: str) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT sha FROM seen_files WHERE repo = ? AND path = ?",
                (repo, path),
            ).fetchone()
        return bool(row and row[0] == sha)

    def mark_file_seen(self, repo: str, path: str, sha: str):
        with self._lock:
            self.conn.execute(
                "INSERT INTO seen_files (repo, path, sha) VALUES (?, ?, ?)"
                " ON CONFLICT(repo, path) DO UPDATE SET sha = excluded.sha",
                (repo, path, sha),
            )
            self.conn.commit()

    def gist_seen(self, gist_id: str, updated_at: str) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT updated_at FROM seen_gists WHERE gist_id = ?", (gist_id,)
            ).fetchone()
        return bool(row and row[0] == updated_at)

    def mark_gist_seen(self, gist_id: str, updated_at: str):
        with self._lock:
            self.conn.execute(
                "INSERT INTO seen_gists (gist_id, updated_at) VALUES (?, ?)"
                " ON CONFLICT(gist_id) DO UPDATE SET updated_at = excluded.updated_at",
                (gist_id, updated_at),
            )
            self.conn.commit()

    def add_processed_shas(self, shas: list[str], max_keep: int = 100000):
        if not shas:
            return
        with self._lock:
            self.conn.executemany(
                "INSERT OR IGNORE INTO seen_shas (sha) VALUES (?)",
                [(sha,) for sha in shas],
            )
            self.conn.execute(
                "DELETE FROM seen_shas WHERE id <= (SELECT COALESCE(MAX(id), 0) - ? FROM seen_shas)",
                (max_keep,),
            )
            self.conn.commit()

    def load_processed_shas(self) -> list[str]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT sha FROM seen_shas ORDER BY id"
            ).fetchall()
        return [row[0] for row in rows]

    def add_watchlist(self, repo: str, size_kb: int | None = None,
                      max_count: int = 0, force: bool = False):
        with self._lock:
            if not force and max_count > 0:
                count = self.conn.execute(
                    "SELECT COUNT(*) FROM watchlist").fetchone()[0]
                if count >= max_count:
                    return
            self.conn.execute(
                "INSERT OR IGNORE INTO watchlist (repo, size_kb, added_at)"
                " VALUES (?, ?, ?)",
                (repo, size_kb, utcnow()),
            )
            self.conn.commit()

    def watchlist_due(self, rescan_days: int, max_size_kb: int,
                      limit: int = 5) -> list[str]:
        cutoff = datetime.now(timezone.utc).timestamp() - rescan_days * 86400
        cutoff_str = datetime.fromtimestamp(cutoff, timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            rows = self.conn.execute(
                "SELECT repo FROM watchlist WHERE"
                " (last_scanned IS NULL OR last_scanned < ?)"
                " AND (size_kb IS NULL OR size_kb <= ?)"
                " ORDER BY added_at LIMIT ?",
                (cutoff_str, max_size_kb, limit),
            ).fetchall()
        return [row[0] for row in rows]

    def mark_watchlist_scanned(self, repo: str):
        with self._lock:
            self.conn.execute(
                "UPDATE watchlist SET last_scanned = ?, fail_count = 0 WHERE repo = ?",
                (utcnow(), repo),
            )
            self.conn.commit()

    def mark_watchlist_failed(self, repo: str) -> int:
        with self._lock:
            self.conn.execute(
                "UPDATE watchlist SET fail_count = fail_count + 1 WHERE repo = ?",
                (repo,),
            )
            row = self.conn.execute(
                "SELECT fail_count FROM watchlist WHERE repo = ?", (repo,)
            ).fetchone()
            self.conn.commit()
        return row[0] if row else 0

    def close(self):
        with self._lock:
            self.conn.close()
