import argparse
import asyncio
import csv
import hashlib
import json
import logging
import os
import re
import sys

import httpx

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from scanner.filters import extract_keys
from scanner.fx import CurrencyConverter
from scanner.storage import Store
from scanner.validator import Validator

log = logging.getLogger("scanner.discord-import")

API = "https://discord.com/api/v10"
SOURCE_RE = re.compile(r"\((https?://[^)\s]+)\)")


def message_text(msg: dict) -> str:
    parts = [msg.get("content") or ""]
    for embed in msg.get("embeds") or []:
        parts.append(embed.get("title") or "")
        parts.append(embed.get("description") or "")
        for field in embed.get("fields") or []:
            parts.append(field.get("name") or "")
            parts.append(field.get("value") or "")
        footer = embed.get("footer")
        if isinstance(footer, dict):
            parts.append(footer.get("text") or "")
    for attachment in msg.get("attachments") or []:
        parts.append(attachment.get("filename") or "")
    return "\n".join(parts)


def message_context(msg: dict) -> dict:
    repo = source_url = balance = None
    for embed in msg.get("embeds") or []:
        for field in embed.get("fields") or []:
            name = (field.get("name") or "").lower()
            value = field.get("value") or ""
            if "repo" in name:
                repo = value.strip()
            elif "balance" in name:
                balance = value.strip()
            elif "source" in name:
                m = SOURCE_RE.search(value)
                if m:
                    source_url = m.group(1)
    return {
        "repo": repo,
        "balance_raw": balance,
        "source_url": source_url,
        "message_id": msg.get("id"),
        "message_date": msg.get("timestamp"),
    }


async def fetch_messages(client: httpx.AsyncClient, token: str, channel: str,
                         is_bot: bool, max_messages: int = 0) -> list[dict]:
    headers = {"Authorization": f"{'Bot ' if is_bot else ''}{token}",
               "User-Agent": "deepseek-scanner"}
    messages: list[dict] = []
    before = None
    while True:
        params = {"limit": 100}
        if before:
            params["before"] = before
        resp = await client.get(f"{API}/channels/{channel}/messages",
                                params=params, headers=headers, timeout=30.0)
        if resp.status_code == 401:
            raise SystemExit("Discord rejected the token (401). Check the token "
                             "and that it has access to this channel.")
        if resp.status_code == 403:
            raise SystemExit("Discord returned 403 - the bot/user lacks "
                             "'Read Message History' or access to this channel.")
        if resp.status_code == 429:
            retry = float(resp.headers.get("Retry-After", "2"))
            log.warning("rate limited, sleeping %.1fs", retry)
            await asyncio.sleep(retry)
            continue
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        messages.extend(batch)
        before = batch[-1]["id"]
        log.info("fetched %d messages (total %d)", len(batch), len(messages))
        if max_messages and len(messages) >= max_messages:
            break
        if len(batch) < 100:
            break
        await asyncio.sleep(0.5)
    return messages


def load_export(path: str) -> list[dict]:
    data = json.load(open(path, encoding="utf-8"))
    if isinstance(data, dict) and "messages" in data:
        return data["messages"]
    if isinstance(data, list):
        return data
    raise SystemExit("Unrecognized export format (expected DiscordChatExporter "
                     "JSON with a 'messages' array)")


async def main():
    parser = argparse.ArgumentParser(
        description="Import DeepSeek keys from a Discord channel or export, "
                    "then validate them.")
    parser.add_argument("--config",
                        default=os.path.join(PROJECT_ROOT, "config.toml"))
    parser.add_argument("--token", default=os.environ.get("DISCORD_TOKEN", ""),
                        help="bot token or user token (or DISCORD_TOKEN env)")
    parser.add_argument("--channel", default="",
                        help="channel id to fetch messages from")
    parser.add_argument("--user-token", action="store_true",
                        help="token is a user token instead of a bot token")
    parser.add_argument("--export-json", default="",
                        help="parse a DiscordChatExporter JSON export instead")
    parser.add_argument("--max", type=int, default=0,
                        help="cap number of messages fetched (0 = all)")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--report", default="discord_import_report.csv")
    parser.add_argument("--notify", action="store_true",
                        help="send funded keys to the configured Discord "
                             "webhook (grouped per repo)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    import tomllib
    cfg = tomllib.load(open(args.config, "rb"))
    pattern = re.compile(cfg.get("key_regex", r"sk-[a-f0-9]{32}\b"))

    if args.export_json:
        messages = load_export(args.export_json)
    elif args.token and args.channel:
        limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
        async with httpx.AsyncClient(http2=True, limits=limits) as client:
            messages = await fetch_messages(client, args.token, args.channel,
                                            not args.user_token, args.max)
    else:
        raise SystemExit("Provide --token + --channel, or --export-json PATH")

    log.info("scanning %d messages for keys", len(messages))
    empty = sum(1 for m in messages
                if not (m.get("content") or "").strip()
                and not (m.get("embeds") or []))
    if messages and empty > len(messages) * 0.5:
        log.warning(
            "%d/%d messages came back with empty content and no embeds. "
            "Your bot is missing the privileged 'Message Content Intent'.",
            empty, len(messages))
        print("\n*** ACTION REQUIRED ***")
        print("Discord stripped all message content/embeds because the bot's")
        print("'Message Content Intent' is disabled. Fix it here:")
        print("  https://discord.com/developers/applications -> your app ->")
        print("  Bot -> Privileged Gateway Intents -> enable")
        print("  'Message Content Intent' -> Save, then re-run this tool.")
        if empty == len(messages):
            print("\nNo keys can be found until this is enabled. Exiting.")
            return

    found: dict[str, dict] = {}
    for msg in messages:
        text = message_text(msg)
        ctx = message_context(msg)
        for key in extract_keys(text, pattern):
            if key not in found:
                found[key] = {**ctx, "key": key}
    log.info("unique candidate keys: %d", len(found))

    store = Store(os.path.join(PROJECT_ROOT, "findings.db"))
    new_keys = []
    for key, ctx in found.items():
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        if store.add_candidate(key_hash=key_hash, key=key,
                               repo=ctx.get("repo") or "discord-import",
                               file_path=None,
                               commit_url=ctx.get("source_url"),
                               author_name=None, author_email=None,
                               source="discord-import"):
            ctx["key_hash"] = key_hash
            new_keys.append((key, ctx))
        else:
            log.info("already known, skipping: %s...", key[:10])
    log.info("new keys to validate: %d (already known: %d)",
             len(new_keys), len(found) - len(new_keys))

    results = []
    if new_keys:
        limits = httpx.Limits(max_connections=40, max_keepalive_connections=20)
        async with httpx.AsyncClient(http2=True, limits=limits) as client:
            validator = Validator(client, concurrency=args.concurrency)
            fx = CurrencyConverter(
                client=client,
                api_url=cfg.get("fx", {}).get(
                    "api_url", "https://open.er-api.com/v6/latest/USD"))
            await fx.ensure()
            for key, ctx in new_keys:
                status, balances = await validator.check(key)
                eur = None
                if balances:
                    converted = [fx.to_eur(a, c) for a, c in balances]
                    known = [v for v in converted if v is not None]
                    if len(known) == len(balances):
                        eur = sum(known)
                label = f"€{eur:.2f}" if eur is not None else None
                key_hash = ctx["key_hash"]
                if status == "invalid":
                    final = "dead-or-other-provider"
                    store.mark_validated(key_hash, "invalid", None)
                elif status == "retry":
                    final = "unknown"
                elif eur is not None and eur > 0:
                    final = "FUNDED"
                    store.mark_validated(key_hash, "valid", label)
                else:
                    final = "authenticated-empty"
                    store.mark_validated(key_hash, "below_threshold", label)
                results.append({**ctx, "key": key, "status": final,
                                "balance_eur": label or ""})
                log.info("%-20s %-10s %s", final, label or "-", key[:12] + "...")

    if args.notify and results:
        from scanner.notifier import Notifier
        funded = [r for r in results if r["status"] == "FUNDED"]
        if funded:
            async with httpx.AsyncClient(http2=True) as client:
                notifier = Notifier(client, cfg.get("discord_webhook_url", ""))
                groups: dict[str, list[dict]] = {}
                for r in funded:
                    groups.setdefault(r.get("repo") or "discord-import",
                                      []).append(r)
                for repo, items in groups.items():
                    await notifier.notify_many(
                        [{"key": i["key"], "balance_eur": i["balance_eur"],
                          "repo": repo, "commit_url": i.get("source_url"),
                          "file_path": None, "author_email": None,
                          "source": "discord-import"} for i in items])

    with open(args.report, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "status", "balance_eur", "key", "repo", "source_url",
            "message_date", "message_id"])
        writer.writeheader()
        for row in sorted(results, key=lambda r: (r["status"] != "FUNDED",
                                                  r["status"])):
            writer.writerow({k: row.get(k, "") for k in writer.fieldnames})

    print()
    print("=== SUMMARY ===")
    for status in ("FUNDED", "authenticated-empty", "unknown",
                   "dead-or-other-provider"):
        n = sum(1 for r in results if r["status"] == status)
        if n:
            print(f"  {status:22s} {n}")
    print(f"  report written to {args.report}")
    funded = [r for r in results if r["status"] == "FUNDED"]
    if funded:
        print()
        print("FUNDED KEYS:")
        for r in funded:
            print(f"  {r['key']}  {r['balance_eur']}  {r.get('repo') or '-'}"
                  f"  {r.get('source_url') or ''}")
    store.close()


if __name__ == "__main__":
    asyncio.run(main())
