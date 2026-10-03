import asyncio
import logging

import httpx

log = logging.getLogger("scanner.validator")

BALANCE_URL = "https://api.deepseek.com/user/balance"


class Validator:
    def __init__(self, client: httpx.AsyncClient, concurrency: int = 5):
        self.client = client
        self.sem = asyncio.Semaphore(concurrency)
        self._ip_blocked: bool | None = None

    async def _ip_blocked_check(self) -> bool:
        if self._ip_blocked is not None:
            return self._ip_blocked
        dummy = "sk-" + "0" * 32
        try:
            resp = await self.client.get(
                BALANCE_URL, headers={"Authorization": f"Bearer {dummy}"},
                timeout=15.0)
            self._ip_blocked = resp.status_code == 403
        except httpx.HTTPError:
            self._ip_blocked = False
        return self._ip_blocked

    async def check(self, key: str) -> tuple[str, list[tuple[float, str]]]:
        async with self.sem:
            headers = {"Authorization": f"Bearer {key}"}
            for attempt in range(2):
                try:
                    resp = await self.client.get(BALANCE_URL, headers=headers, timeout=15.0)
                except httpx.HTTPError as exc:
                    log.warning("balance check transport error: %s", exc)
                    if attempt == 0:
                        await asyncio.sleep(2)
                        continue
                    return "retry", []

                if resp.status_code == 200:
                    try:
                        valid, balances = self._parse(resp.json())
                    except ValueError:
                        log.warning("balance check returned non-JSON")
                        return "retry", []
                    return ("valid" if valid else "invalid"), balances
                if resp.status_code == 401:
                    return "invalid", []
                if resp.status_code == 403:
                    if await self._ip_blocked_check():
                        log.warning("balance check HTTP 403 (IP-level block), deferring")
                        if attempt == 0:
                            await asyncio.sleep(3)
                            continue
                        return "retry", []
                    log.info("balance check HTTP 403: key is valid but restricted")
                    return "valid", []
                if resp.status_code == 429:
                    backoff = 5 * (attempt + 1)
                    log.warning("balance check rate limited (429), sleeping %ds", backoff)
                    await asyncio.sleep(backoff)
                    continue
                if attempt == 0:
                    await asyncio.sleep(2)
                    continue
                log.warning("balance check HTTP %d", resp.status_code)
                return "retry", []

        return "retry", []

    @staticmethod
    def _parse(data) -> tuple[bool, list[tuple[float, str]]]:
        if not isinstance(data, dict):
            return False, []
        balances = []
        for info in data.get("balance_infos") or []:
            try:
                amount = float(info.get("total_balance"))
            except (TypeError, ValueError):
                continue
            currency = info.get("currency")
            if currency:
                balances.append((amount, str(currency)))
        return True, balances
