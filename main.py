import html
import json
import logging
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ============================================================
# CONFIG
# ============================================================

BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]

PROFILE_URL = "https://api.dexscreener.com/token-profiles/latest/v1"
TOKEN_URL = "https://api.dexscreener.com/tokens/v1"

SEEN_FILE = "seen.json"
BLACKLIST_FILE = "blacklist.json"

MAX_PER_RUN = 10


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

log = logging.getLogger(__name__)


# ============================================================
# HTTP SESSION
# ============================================================

session = requests.Session()

retry = Retry(
    total=3,
    connect=3,
    read=3,
    backoff_factor=1,
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
    response = session.get(
        PROFILE_URL,
        timeout=20
    )

    response.raise_for_status()

    data = response.json()

    return [data] if isinstance(data, dict) else data


def get_token_pairs(chain, address):
    url = f"{TOKEN_URL}/{chain}/{address}"

    response = session.get(
        url,
        timeout=20
    )

    response.raise_for_status()

    data = response.json()

    return data if isinstance(data, list) else []


# ============================================================
# FORMATTING
# ============================================================

def format_number(value):
    if value is None:
        return "N/A"

    try:
        value = float(value)

        if value >= 1_000_000_000:
            return f"${value / 1_000_000_000:.2f}B"

        if value >= 1_000_000:
            return f"${value / 1_000_000:.2f}M"

        if value >= 1_000:
            return f"${value / 1_000:.2f}K"

        if value >= 1:
            return f"${value:.2f}"

        return f"${value:.8f}"

    except (ValueError, TypeError):
        return "N/A"


def format_age(timestamp):
    if not timestamp:
        return "N/A"

    try:
        created = datetime.fromtimestamp(
            timestamp / 1000,
            tz=timezone.utc
        )

        now = datetime.now(timezone.utc)

        seconds = max(
            0,
            int((now - created).total_seconds())
        )

        if seconds < 60:
            return f"{seconds}s"

        minutes = seconds // 60

        if minutes < 60:
            return f"{minutes}m"

        hours = minutes // 60

        if hours < 24:
            return f"{hours}h"

        return f"{hours // 24}d"

    except (ValueError, TypeError, OverflowError):
        return "N/A"


def clean_text(value, limit=700):
    if not value:
        return ""

    value = str(value).strip()

    return html.escape(value[:limit])


def valid_url(url):
    if not url:
        return False

    try:
        parsed = urlparse(url)

        return parsed.scheme in ("http", "https") and bool(
            parsed.netloc
        )

    except Exception:
        return False


# ============================================================
# LINKS
# ============================================================

def build_buttons(token, dex_url):
    buttons = []

    if valid_url(dex_url):
        buttons.append({
            "text": "📊 DexScreener",
            "url": dex_url
        })

    links = token.get("links") or []

    for link in links:
        if not isinstance(link, dict):
            continue

        url = link.get("url")

        if not valid_url(url):
            continue

        label = (
            link.get("label")
            or link.get("type")
            or "Website"
        )

        label = str(label).strip()

        if len(label) > 24:
            label = label[:21] + "..."

        buttons.append({
            "text": f"🔗 {label}",
            "url": url
        })

    # Remove duplicate URLs
    unique = []
    seen_urls = set()

    for button in buttons:
        if button["url"] in seen_urls:
            continue

        seen_urls.add(button["url"])
        unique.append(button)

    # Maximum 6 buttons
    unique = unique[:6]

    # Two buttons per row
    return [
        unique[i:i + 2]
        for i in range(0, len(unique), 2)
    ]


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

    dex_url = (
        pair.get("url")
        or token.get("url")
        or ""
    )

    price = pair.get("priceUsd")

    liquidity = (
        pair.get("liquidity") or {}
    ).get("usd")

    volume = (
        pair.get("volume") or {}
    ).get("h24")

    market_cap = (
        pair.get("marketCap")
        or pair.get("fdv")
    )

    transactions = (
        pair.get("txns") or {}
    ).get("h24") or {}

    buys = transactions.get("buys", 0)
    sells = transactions.get("sells", 0)

    price_change = (
        pair.get("priceChange") or {}
    ).get("h24")

    age = format_age(
        pair.get("pairCreatedAt")
    )

    description = clean_text(
        token.get("description"),
        700
    )

    if price_change is not None:
        try:
            change = float(price_change)
            change_text = f"{change:+.2f}%"
        except (ValueError, TypeError):
            change_text = "N/A"
    else:
        change_text = "N/A"

    # Escape token name/symbol/address/etc.
    safe_name = html.escape(str(name))
    safe_symbol = html.escape(str(symbol))
    safe_chain = html.escape(str(chain))
    safe_dex = html.escape(str(dex))
    safe_address = html.escape(str(address))

    message = (
        "🚨 <b>NEW TOKEN DETECTED</b>\n\n"

        f"🪙 <b>{safe_name}</b> "
        f"<code>${safe_symbol}</code>\n\n"

        f"⛓ <b>Chain:</b> {safe_chain}\n"
        f"🏪 <b>DEX:</b> {safe_dex}\n"
        f"⏱ <b>Pair Age:</b> {age}\n\n"

        f"💵 <b>Price:</b> {format_number(price)}\n"
        f"💧 <b>Liquidity:</b> "
        f"{format_number(liquidity)}\n"
        f"📊 <b>24h Volume:</b> "
        f"{format_number(volume)}\n"
        f"💰 <b>Market Cap:</b> "
        f"{format_number(market_cap)}\n"
        f"📈 <b>24h Change:</b> "
        f"{change_text}\n\n"

        f"🟢 <b>Buys:</b> {buys}\n"
        f"🔴 <b>Sells:</b> {sells}\n\n"

        f"📜 <b>Contract</b>\n"
        f"<code>{safe_address}</code>\n\n"

        "🛡 <b>Security:</b> "
        "Not analysed yet"
    )

    if description:
        message += (
            f"\n\n📝 <b>About:</b>\n"
            f"{description}"
        )

    return message, dex_url


# ============================================================
# TELEGRAM
# ============================================================

def send_telegram(message, token, dex_url):
    buttons = build_buttons(
        token,
        dex_url
    )

    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    if buttons:
        payload["reply_markup"] = {
            "inline_keyboard": buttons
        }

    url = (
        f"https://api.telegram.org/"
        f"bot{BOT_TOKEN}/sendMessage"
    )

    response = requests.post(
        url,
        json=payload,
        timeout=20
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# MAIN
# ============================================================

def main():
    seen = load_json(SEEN_FILE)

    seen_set = set(seen)

    blacklist = {
        str(address).lower()
        for address in load_json(BLACKLIST_FILE)
    }

    sent = 0

    # Prevent duplicate processing during this run
    run_processed = set()

    try:
        tokens = get_latest_tokens()

        log.info(
            "DexScreener returned %d token profiles",
            len(tokens)
        )

        for token in tokens:

            if sent >= MAX_PER_RUN:
                break

            if not isinstance(token, dict):
                continue

            chain = token.get("chainId")
            address = token.get("tokenAddress")

            if not chain or not address:
                continue

            token_id = f"{chain}:{address}"

            # Already permanently processed
            if token_id in seen_set:
                continue

            # Duplicate in same API response
            if token_id in run_processed:
                continue

            run_processed.add(token_id)

            # ------------------------------------------------
            # BLACKLIST
            # ------------------------------------------------

            if address.lower() in blacklist:
                log.info(
                    "Blacklisted token skipped: %s",
                    token_id
                )

                seen.append(token_id)
                seen_set.add(token_id)

                continue

            # ------------------------------------------------
            # GET PAIR DATA
            # ------------------------------------------------

            try:
                pairs = get_token_pairs(
                    chain,
                    address
                )

                if not pairs:
                    log.warning(
                        "No pair data: %s",
                        token_id
                    )

                    # IMPORTANT:
                    # Do NOT mark as seen.
                    # It can be retried next run.
                    continue

                # Pick highest-liquidity pair
                pair = max(
                    pairs,
                    key=lambda p: float(
                        (
                            p.get("liquidity") or {}
                        ).get("usd") or 0
                    )
                )

            except Exception as e:
                log.exception(
                    "Pair lookup failed for %s: %s",
                    token_id,
                    e
                )

                # Do NOT mark as seen.
                continue

            # ------------------------------------------------
            # BUILD + SEND
            # ------------------------------------------------

            try:
                message, dex_url = build_message(
                    token,
                    pair
                )

                send_telegram(
                    message,
                    token,
                    dex_url
                )

                sent += 1

                # Only mark seen AFTER successful Telegram send
                seen.append(token_id)
                seen_set.add(token_id)

                log.info(
                    "Alert sent: %s / %s",
                    chain,
                    pair.get("baseToken", {}).get(
                        "symbol",
                        "???"
                    )
                )

            except Exception as e:
                log.exception(
                    "Telegram/send failed for %s: %s",
                    token_id,
                    e
                )

                # Do NOT mark as seen.
                # Failed alerts can retry next run.

    finally:
        # Keep state under control
        seen = seen[-1000:]

        save_json(
            SEEN_FILE,
            seen
        )

        log.info(
            "Run complete | alerts sent: %d",
            sent
        )


if __name__ == "__main__":
    main()
