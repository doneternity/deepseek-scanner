import base64
import math
import re
import urllib.parse

B64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,64}={0,2})(?![A-Za-z0-9+/=])"
)
CONCAT_RE = re.compile(
    r"(?:\"[^\"\n]{0,60}\"|'[^'\n]{0,60}')"
    r"(?:\s*\+\s*(?:\"[^\"\n]{0,60}\"|'[^'\n]{0,60}'))+"
)
HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){12,}")
HEX_STRING_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{60,90}(?![0-9A-Fa-f])")
PCT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){12,}")
REVERSED_RE = re.compile(r"\b([0-9a-f]{32}-ks)\b")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_keys(text: str, pattern: re.Pattern):
    if not text:
        return
    seen: set[str] = set()

    def emit(candidate: str):
        for m in pattern.finditer(candidate):
            key = m.group(0)
            if key not in seen:
                seen.add(key)
                yield key

    yield from emit(text)

    for m in B64_RE.finditer(text):
        blob = m.group(1)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4),
                                       validate=True)
            decoded_text = decoded.decode("utf-8")
        except (ValueError, TypeError, UnicodeDecodeError):
            continue
        yield from emit(decoded_text)

    for m in CONCAT_RE.finditer(text):
        parts = re.findall(r"\"([^\"\n]*)\"|'([^'\n]*)'", m.group(0))
        joined = "".join(a or b for a, b in parts)
        yield from emit(joined)

    for m in HEX_ESCAPE_RE.finditer(text):
        try:
            decoded_text = bytes.fromhex(
                m.group(0).replace("\\x", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        yield from emit(decoded_text)

    for m in HEX_STRING_RE.finditer(text):
        try:
            decoded_text = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        yield from emit(decoded_text)

    for m in PCT_RE.finditer(text):
        yield from emit(urllib.parse.unquote(m.group(0)))

    for m in REVERSED_RE.finditer(text):
        yield from emit(m.group(1)[::-1])


def is_placeholder(key: str, denylist: frozenset[str] = frozenset()) -> bool:
    if key in denylist:
        return True
    body = key[3:] if key.startswith("sk-") else key
    if not body:
        return True
    if len(set(body)) <= 2:
        return True
    if shannon_entropy(body) < 2.5:
        return True
    return False
