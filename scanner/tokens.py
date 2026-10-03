import asyncio
import threading

from scanner.ratelimit import TokenBucket


class TokenPool:
    def __init__(self, tokens: list[str], rate: float, capacity: float):
        self.pairs = [(tok, TokenBucket(rate, capacity)) for tok in tokens]
        self._lock = threading.Lock()

    @property
    def size(self) -> int:
        return len(self.pairs)

    async def acquire(self) -> str:
        while True:
            with self._lock:
                for tok, bucket in self.pairs:
                    if bucket.try_acquire():
                        return tok
            wait = min(bucket.time_until() for _, bucket in self.pairs)
            await asyncio.sleep(max(0.05, wait))
