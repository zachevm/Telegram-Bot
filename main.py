import asyncio
import html
import json
import logging
import os
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from telethon import TelegramClient
from telethon.sessions import StringSession

# ============================================================
# CONFIG
# ============================================================

API_ID = int(os.environ["TELEGRAM_API_ID"])
API_HASH = os.environ["TELEGRAM_API_HASH"]
SESSION_STRING = os.environ["TELEGRAM_SESSION"]

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
USER_CHAT_ID = os.environ.get("TELEGRAM_USER_CHAT_ID")
GROUP_ID = os.environ.get("TELEGRAM_GROUP_ID")

# The group is the Telethon destination used for Phanes analysis.
GROUP_IDS = []
if GROUP_ID:
    try:
        GROUP_IDS.append(int(GROUP_ID.strip()))
    except ValueError:
        GROUP_IDS.append(GROUP_ID.strip())

PROFILE_URL = "https://api.dexscreener.com/token-profiles/latest/v1"
TOKEN_URL = "https://api.dexscreener.com/tokens/v1"

SEEN_FILE = "seen.json"
BLACKLIST_FILE = "blacklist.json"

# Discovery controls
MAX_CANDIDATES = 20
MAX_ALERTS_PER_RUN = 5
MIN_DISCOVERY_SCORE = 35
ALERT_DELAY_SECONDS = 30

# Hard filters (a token failing any of these is rejected before scoring)
MIN_LIQUIDITY_USD = 5_000
MIN_TOTAL_TRADES = 20
MIN_SELLS = 3  # near-zero sells is a classic honeypot signal
MAX_PAIR_AGE_HOURS = 168  # reject pairs older than 7 days (profile feed returns many old tokens)
MAX_PRICE_CHANGE_24H = 500  # reject if already up more than 500% in 24h (not early)

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
log = logging.getLogger(__name__)

# ============================================================
# HTTP SESSION (For DexScreener & Bot API)
# ============================================================

session = requests.Session()
retry = Retry(
    total=3, connect=3, read=3, backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["GET"]),
)
adapter = HTTPAdapter(max_retries=retry)
session.mount("https://", adapter)
session.mount("http://", adapter)

# ============================================================
# FILE HELPERS
# ============================================================

def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# ============================================================
# DEXSCREENER
# ============================================================

def get_latest_tokens():
    response = session.get(PROFILE_URL, timeout=20)
    response.raise_for_status()
    data = response.json()
    return [data] if isinstance(data, dict) else data

def get_token_pairs(chain, address):
    url = f"{TOKEN_URL}/{chain}/{address}"
    response = session.get(url, timeout=20)
    response.raise_for_status()
    data = response.json()
    return data if isinstance(data, list) else []

# ============================================================
# FILTERS & DISCOVERY SCORING
# ============================================================

def hard_filter_reason(pair):
    """Return why a pair is rejected, or None if it passes every hard filter."""
    try:
        liquidity = float((pair.get("liquidity") or {}).get("usd") or 0)
        tx = (pair.get("txns") or {}).get("h24") or {}
        buys = int(tx.get("buys") or 0)
        sells = int(tx.get("sells") or 0)
    except (ValueError, TypeError):
        return "bad data"

    if liquidity < MIN_LIQUIDITY_USD:
        return "liquidity"
    if buys + sells < MIN_TOTAL_TRADES:
        return "trades"
    if sells < MIN_SELLS:
        return "sells"

    # Age gate: unknown age is rejected because "early" can't be verified
    created_at = pair.get("pairCreatedAt")
    if not created_at:
        return "no age"
    try:
        created = datetime.fromtimestamp(created_at / 1000, tz=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - created).total_seconds() / 3600
    except (ValueError, TypeError, OverflowError):
        return "no age"
    if age_hours > MAX_PAIR_AGE_HOURS:
        return "age"

    # Price-change ceiling: a token already up massively is not early
    change = (pair.get("priceChange") or {}).get("h24")
    if change is not None:
        try:
            if float(change) > MAX_PRICE_CHANGE_24H:
                return "price change"
        except (ValueError, TypeError):
            pass

    return None

def calculate_discovery_score(pair):
    score = 0
    liquidity = float((pair.get("liquidity") or {}).get("usd") or 0)
    volume = float((pair.get("volume") or {}).get("h24") or 0)
    market_cap = float(pair.get("marketCap") or pair.get("fdv") or 0)
    transactions = (pair.get("txns") or {}).get("h24") or {}
    buys = int(transactions.get("buys") or 0)
    sells = int(transactions.get("sells") or 0)
    total_trades = buys + sells
    age = pair.get("pairCreatedAt")

    if liquidity >= 100_000: score += 25
    elif liquidity >= 50_000: score += 20
    elif liquidity >= 10_000: score += 12
    elif liquidity >= 5_000: score += 5

    if volume >= 100_000: score += 20
    elif volume >= 50_000: score += 15
    elif volume >= 10_000: score += 10
    elif volume >= 1_000: score += 5

    if total_trades >= 500: score += 20
    elif total_trades >= 200: score += 15
    elif total_trades >= 50: score += 10
    elif total_trades >= 10: score += 5

    if total_trades > 0:
        buy_ratio = buys / total_trades
        if 0.35 <= buy_ratio <= 0.65: score += 10
        elif 0.20 <= buy_ratio <= 0.80: score += 5

    if market_cap > 0:
        liquidity_ratio = liquidity / market_cap
        if liquidity_ratio >= 0.10: score += 15
        elif liquidity_ratio >= 0.05: score += 10
        elif liquidity_ratio >= 0.02: score += 5

    if age:
        try:
            created = datetime.fromtimestamp(age / 1000, tz=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - created).total_seconds() / 3600
            if 1 <= age_hours <= 72: score += 10
            elif age_hours <= 168: score += 5
        except (ValueError, TypeError, OverflowError):
            pass

    return score

# ============================================================
# FORMATTING
# ============================================================

def format_number(value):
    if value is None: return "N/A"
    try:
        value = float(value)
        if value >= 1_000_000_000: return f"${value / 1_000_000_000:.2f}B"
        if value >= 1_000_000: return f"${value / 1_000_000:.2f}M"
        if value >= 1_000: return f"${value / 1_000:.2f}K"
        if value >= 1: return f"${value:.2f}"
        return f"${value:.8f}"
    except (ValueError, TypeError):
        return "N/A"

def format_age(timestamp):
    if not timestamp: return "N/A"
    try:
        created = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        seconds = max(0, int((now - created).total_seconds()))

        if seconds < 60: return f"{seconds}s"
        minutes = seconds // 60
        if minutes < 60: return f"{minutes}m"
        hours = minutes // 60
        if hours < 24: return f"{hours}h"
        return f"{hours // 24}d"
    except (ValueError, TypeError, OverflowError):
        return "N/A"

def clean_text(value, limit=700):
    if not value: return ""
    return html.escape(str(value).strip()[:limit])

def valid_url(url):
    if not url: return False
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

# ============================================================
# TELEGRAM LINKS (Converted from buttons)
# ============================================================

def build_links_text(token, dex_url):
    links = []
    seen_urls = set()

    if valid_url(dex_url):
        links.append(f'<a href="{dex_url}">📊 DexScreener</a>')
        seen_urls.add(dex_url)

    token_links = token.get("links") or []

    for link in token_links:
        if not isinstance(link, dict): continue
        url = link.get("url")
        if not valid_url(url) or url in seen_urls: continue

        label = str(link.get("label") or link.get("type") or "Website").strip()
        if len(label) > 24: label = label[:21] + "..."

        links.append(f'<a href="{url}">🔗 {html.escape(label)}</a>')
        seen_urls.add(url)

    if not links:
        return ""

    return "🌐 <b>Links:</b>\n" + " | ".join(links[:6])

# ============================================================
# TELEGRAM MESSAGE
# ============================================================

def build_message(token, pair):
    chain = token.get("chainId", "Unknown")
    address = token.get("tokenAddress", "Unknown")
    base_token = pair.get("baseToken") or {}

    name = base_token.get("name") or "Unknown"
    symbol = base_token.get("symbol") or "???"
    dex = pair.get("dexId") or "Unknown"
    dex_url = pair.get("url") or token.get("url") or ""

    price = pair.get("priceUsd")
    liquidity = (pair.get("liquidity") or {}).get("usd")
    volume = (pair.get("volume") or {}).get("h24")
    market_cap = pair.get("marketCap") or pair.get("fdv")

    transactions = (pair.get("txns") or {}).get("h24") or {}
    buys = transactions.get("buys", 0)
    sells = transactions.get("sells", 0)

    price_change = (pair.get("priceChange") or {}).get("h24")
    age = format_age(pair.get("pairCreatedAt"))
    description = clean_text(token.get("description"), 700)

    if price_change is not None:
        try:
            change_text = f"{float(price_change):+.2f}%"
        except (ValueError, TypeError):
            change_text = "N/A"
    else:
        change_text = "N/A"

    safe_name = html.escape(str(name))
    safe_symbol = html.escape(str(symbol))
    safe_chain = html.escape(str(chain))
    safe_dex = html.escape(str(dex))
    safe_address = html.escape(str(address))

    message = (
        "🚨 <b>TOKEN ALERT</b>\n\n"
        f"🪙 <b>{safe_name}</b> <code>${safe_symbol}</code>\n\n"
        f"⛓ <b>Chain:</b> {safe_chain}\n"
        f"🏪 <b>DEX:</b> {safe_dex}\n"
        f"⏱ <b>Pair Age:</b> {age}\n\n"
        f"💵 <b>Price:</b> {format_number(price)}\n"
        f"💧 <b>Liquidity:</b> {format_number(liquidity)}\n"
        f"📊 <b>24h Volume:</b> {format_number(volume)}\n"
        f"💰 <b>Market Cap:</b> {format_number(market_cap)}\n"
        f"📈 <b>24h Change:</b> {change_text}\n\n"
        f"🟢 <b>Buys:</b> {buys}\n"
        f"🔴 <b>Sells:</b> {sells}\n\n"
        f"📜 <b>Contract</b>\n<code>{safe_address}</code>\n\n"
        "🛡 <b>Security:</b> Not analysed yet"
    )

    if description:
        message += f"\n\n📝 <b>About:</b>\n{description}"

    links_text = build_links_text(token, dex_url)
    if links_text:
        message += f"\n\n{links_text}"

    return message

# ============================================================
# TELEGRAM SENDING
# ============================================================

def send_bot_dm(message):
    """Sends the alert to your private bot chat. Returns True only on success."""
    if not BOT_TOKEN:
        log.error("Bot DM skipped: TELEGRAM_BOT_TOKEN is missing from environment.")
        return False
    if not USER_CHAT_ID:
        log.error("Bot DM skipped: TELEGRAM_USER_CHAT_ID is missing from environment.")
        return False

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": USER_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code != 200:
            log.error("Telegram Bot API Error %s: %s", response.status_code, response.text)
            return False
        log.info("Bot DM sent successfully to %s", USER_CHAT_ID)
        return True
    except Exception as e:
        log.exception("Failed to send DM via bot: %s", e)
        return False

async def send_telegram(client, message):
    """Sends the alert to the group via Telethon. Returns the number of successful sends."""
    successful_sends = 0

    for chat_id in GROUP_IDS:
        try:
            await client.send_message(
                chat_id,
                message,
                parse_mode="HTML",
                link_preview=False
            )
            successful_sends += 1
            log.info("Telegram alert sent to %s", chat_id)
        except Exception as e:
            log.exception("Telegram send failed for %s: %s", chat_id, e)

    return successful_sends

# ============================================================
# MAIN
# ============================================================

async def main():
    seen = load_json(SEEN_FILE)
    seen_set = set(seen)
    blacklist = {str(address).lower() for address in load_json(BLACKLIST_FILE)}

    sent = 0
    run_processed = set()
    candidates = []
    session_failed = False
    stats = Counter()

    try:
        tokens = get_latest_tokens()
        log.info("DexScreener returned %d token profiles", len(tokens))
        stats["profiles"] = len(tokens)

        # ----------------------------------------------------
        # DISCOVERY
        # ----------------------------------------------------
        for token in tokens:
            if len(candidates) >= MAX_CANDIDATES: break
            if not isinstance(token, dict): continue

            chain = token.get("chainId")
            address = token.get("tokenAddress")
            if not chain or not address: continue

            token_id = f"{chain}:{address}"
            if token_id in seen_set or token_id in run_processed:
                stats["already seen"] += 1
                continue

            run_processed.add(token_id)

            if address.lower() in blacklist:
                log.info("Blacklisted token skipped: %s", token_id)
                seen.append(token_id)
                seen_set.add(token_id)
                continue

            try:
                pairs = get_token_pairs(chain, address)
                if not pairs:
                    log.warning("No pair data: %s", token_id)
                    stats["no pair data"] += 1
                    continue

                # Keep only pairs where the profiled token is the base token,
                # otherwise name/symbol shown would belong to the quote token.
                pairs = [
                    p for p in pairs
                    if str((p.get("baseToken") or {}).get("address") or "").lower() == address.lower()
                ]
                if not pairs:
                    log.info("Profiled token is not a base token in any pair: %s", token_id)
                    stats["not base token"] += 1
                    continue

                pair = max(
                    pairs,
                    key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0)
                )
            except Exception as e:
                log.exception("Candidate analysis failed for %s: %s", token_id, e)
                stats["lookup error"] += 1
                continue

            reason = hard_filter_reason(pair)
            if reason:
                log.info("Hard filter rejected (%s): %s", reason, token_id)
                stats[f"rejected: {reason}"] += 1
                continue

            score = calculate_discovery_score(pair)
            if score < MIN_DISCOVERY_SCORE:
                stats["low score"] += 1
                continue

            candidates.append({
                "token": token,
                "pair": pair,
                "token_id": token_id,
                "score": score
            })

            log.info("Candidate accepted: %s | score=%d", token_id, score)

        # ----------------------------------------------------
        # RANK & SEND
        # ----------------------------------------------------
        candidates.sort(key=lambda item: item["score"], reverse=True)
        log.info("Qualified candidates: %d", len(candidates))

        if not candidates:
            return

        # Telethon client: connect and verify the session instead of start(),
        # which can hang waiting for a phone number prompt on a CI runner.
        client = None
        group_ready = False
        try:
            client = TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH)
            await client.connect()
            group_ready = await client.is_user_authorized()
            if not group_ready:
                log.error("Telethon session is invalid or expired. Generate a new TELEGRAM_SESSION. "
                          "Group delivery is disabled for this run; DMs will still be sent.")
        except Exception as e:
            log.exception("Telethon connection failed: %s", e)

        if not group_ready:
            session_failed = True

        try:
            for alert_index, candidate in enumerate(candidates[:MAX_ALERTS_PER_RUN]):
                # Pace consecutive scanner alerts; the first alert is sent immediately.
                if alert_index > 0 and ALERT_DELAY_SECONDS > 0:
                    log.info("Waiting %s seconds before the next alert", ALERT_DELAY_SECONDS)
                    await asyncio.sleep(ALERT_DELAY_SECONDS)

                token = candidate["token"]
                pair = candidate["pair"]
                token_id = candidate["token_id"]
                score = candidate["score"]

                try:
                    message = build_message(token, pair)

                    # 1. Telethon sends to the group (triggers Phanes).
                    destinations = 0
                    if group_ready:
                        destinations = await send_telegram(client, message)

                    # 2. Bot API sends to your private chat. Runs even if the group send fails.
                    dm_ok = send_bot_dm(message)

                    # Only mark the token as seen if at least one delivery succeeded,
                    # so a failed delivery gets retried on the next run.
                    stats["group sends"] += destinations
                    stats["dm sends"] += 1 if dm_ok else 0
                    if destinations > 0 or dm_ok:
                        sent += 1
                        seen.append(token_id)
                        seen_set.add(token_id)
                        log.info("Alert sent: %s | score=%d | group=%d | dm=%s",
                                 token_id, score, destinations, dm_ok)
                    else:
                        log.error("No delivery for %s, will retry next run", token_id)
                        stats["no delivery"] += 1
                except Exception as e:
                    log.exception("Alert failed for %s: %s", token_id, e)
        finally:
            if client is not None:
                try:
                    await client.disconnect()
                except Exception:
                    pass

    finally:
        seen = seen[-1000:]
        save_json(SEEN_FILE, seen)
        rejected = ", ".join(
            f"{k.replace('rejected: ', '')} {v}"
            for k, v in sorted(stats.items()) if k.startswith("rejected: ")
        ) or "none"
        log.info(
            "SUMMARY | profiles: %d | already seen: %d | no pair data: %d | not base token: %d | "
            "lookup errors: %d | hard-filter rejects: [%s] | low score: %d | accepted: %d | "
            "group sends: %d | dm sends: %d | no delivery: %d",
            stats["profiles"], stats["already seen"], stats["no pair data"], stats["not base token"],
            stats["lookup error"], rejected, stats["low score"], len(candidates),
            stats["group sends"], stats["dm sends"], stats["no delivery"],
        )
        log.info("Run complete | alerts sent: %d | candidates: %d", sent, len(candidates))

    # Make a dead session visible: the run shows red in Actions instead of looking healthy.
    if session_failed:
        raise SystemExit(1)

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    asyncio.run(main())
