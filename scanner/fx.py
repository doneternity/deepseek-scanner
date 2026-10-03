import asyncio
import logging
import time

import httpx

log = logging.getLogger("scanner.fx")

FALLBACK_RATES = {
    "USD": 1.0,
    "EUR": 0.92,
    "CNY": 7.1,
}


class CurrencyConverter:
    def __init__(self, client: httpx.AsyncClient, api_url: str = "",
                 ttl_seconds: int = 21600):
        self.client = client
        self.api_url = api_url
        self.ttl = ttl_seconds
        self.rates = dict(FALLBACK_RATES)
        self.fetched_at = 0.0
        self.using_fallback = True
        self._lock = asyncio.Lock()

    async def ensure(self):
        if not self.api_url:
            return
        async with self._lock:
            if self.fetched_at and time.time() - self.fetched_at < self.ttl:
                return
            try:
                resp = await self.client.get(self.api_url, timeout=15.0)
                if resp.status_code == 200:
                    data = resp.json()
                    rates = data.get("rates") or {}
                    fresh = {"USD": 1.0}
                    for cur, val in rates.items():
                        try:
                            fresh[cur.upper()] = float(val)
                        except (TypeError, ValueError):
                            continue
                    if "EUR" in fresh:
                        self.rates = fresh
                        self.fetched_at = time.time()
                        self.using_fallback = False
                        log.info("fx rates fetched (%d currencies)", len(fresh))
                    else:
                        log.warning("fx response missing EUR rate, keeping fallback")
                        self._failed()
                else:
                    log.warning("fx HTTP %d, keeping fallback rates", resp.status_code)
                    self._failed()
            except (httpx.HTTPError, ValueError) as exc:
                log.warning("fx fetch failed (%s), keeping fallback rates", exc)
                self._failed()

    def _failed(self):
        self.fetched_at = time.time() - self.ttl + 1800

    def to_eur(self, amount: float, currency: str) -> float | None:
        cur = (currency or "USD").upper()
        if cur == "EUR":
            return amount
        rate = self.rates.get(cur)
        if rate is None or rate == 0:
            return None
        eur_rate = self.rates.get("EUR")
        if eur_rate is None or eur_rate == 0:
            return None
        return amount / rate * eur_rate
