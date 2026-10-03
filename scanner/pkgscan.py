import logging
import re
import tarfile
import zipfile

from scanner.filters import extract_keys, is_placeholder

log = logging.getLogger("scanner.pkgscan")

MAX_FILE_SIZE = 2_000_000


def scan_archive(path: str, pattern: re.Pattern,
                 deny: frozenset[str] = frozenset()) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    seen: set[str] = set()

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > MAX_FILE_SIZE:
                    continue
                try:
                    data = zf.read(info)
                except (OSError, zipfile.BadZipFile):
                    continue
                _scan_bytes(info.filename, data, pattern, deny, seen, results)
        return results

    try:
        with tarfile.open(path, "r:*") as tf:
            for member in tf:
                if not member.isfile() or member.size > MAX_FILE_SIZE:
                    continue
                f = tf.extractfile(member)
                if f is None:
                    continue
                _scan_bytes(member.name, f.read(), pattern, deny, seen, results)
    except (tarfile.TarError, OSError):
        log.debug("tar scan failed for %s", path)
    return results


def _scan_bytes(name: str, data: bytes, pattern: re.Pattern,
                deny: frozenset[str], seen: set[str],
                results: list[tuple[str, str]]):
    if b"\x00" in data[:4096]:
        return
    try:
        text = data.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        return
    for key in extract_keys(text, pattern):
        if is_placeholder(key, deny) or key in seen:
            continue
        seen.add(key)
        results.append((name, key))
