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

CHAT_IDS = [
    chat_id.strip()
    for chat_id in os.environ["TELEGRAM_CHAT_IDS"].split(",")
    if chat_id.strip()
]

PROFILE_URL = "https://api.dexscreener.com/token-profiles/latest/v1"
TOKEN_URL = "https://api.dexscreener.com/tokens/v1"

SEEN_FILE = "seen.json"
BLACKLIST_FILE = "blacklist.json"

# Discovery controls
MAX_CANDIDATES = 20
MAX_ALERTS_PER_RUN = 5
MIN_DISCOVERY_SCORE = 35


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
# DISCOVERY SCORING
# ============================================================

def calculate_discovery_score(pair):
    """
    Scores how interesting a token is for discovery.

    This is NOT a scam score.
    This is NOT a safety score.

    It is only used to prioritize which fresh tokens
    deserve a Telegram alert.
    """

    score = 0

    liquidity = float(
        (pair.get("liquidity") or {}).get("usd") or 0
    )

    volume = float(
        (pair.get("volume") or {}).get("h24") or 0
    )

    market_cap = float(
        pair.get("marketCap")
        or pair.get("fdv")
        or 0
    )

    transactions = (
        pair.get("txns") or {}
    ).get("h24") or {}

    buys = int(transactions.get("buys") or 0)
    sells = int(transactions.get("sells") or 0)

    total_trades = buys + sells

    age = pair.get("pairCreatedAt")

    # --------------------------------------------------------
    # Liquidity
    # --------------------------------------------------------

    if liquidity >= 100_000:
        score += 25

    elif liquidity >= 50_000:
        score += 20

    elif liquidity >= 10_000:
        score += 12

    elif liquidity >= 5_000:
        score += 5

    # --------------------------------------------------------
    # 24h Volume
    # --------------------------------------------------------

    if volume >= 100_000:
        score += 20

    elif volume >= 50_000:
        score += 15

    elif volume >= 10_000:
        score += 10

    elif volume >= 1_000:
        score += 5

    # --------------------------------------------------------
    # Trading activity
    # --------------------------------------------------------

    if total_trades >= 500:
        score += 20

    elif total_trades >= 200:
        score += 15

    elif total_trades >= 50:
        score += 10

    elif total_trades >= 10:
        score += 5

    # --------------------------------------------------------
    # Buy / sell balance
    # --------------------------------------------------------

    if total_trades > 0:

        buy_ratio = buys / total_trades

        if 0.35 <= buy_ratio <= 0.65:
            score += 10

        elif 0.20 <= buy_ratio <= 0.80:
            score += 5

    # --------------------------------------------------------
    # Liquidity relative to market cap
    # --------------------------------------------------------

    if market_cap > 0:

        liquidity_ratio = liquidity / market_cap

        if liquidity_ratio >= 0.10:
            score += 15

        elif liquidity_ratio >= 0.05:
            score += 10

        elif liquidity_ratio >= 0.02:
            score += 5

    # --------------------------------------------------------
    # Pair age
    # --------------------------------------------------------

    if age:

        try:
            created = datetime.fromtimestamp(
                age / 1000,
                tz=timezone.utc
            )

            age_hours = (
                datetime.now(timezone.utc) - created
            ).total_seconds() / 3600

            if 1 <= age_hours <= 72:
                score += 10

            elif age_hours <= 168:
                score += 5

        except (
            ValueError,
            TypeError,
            OverflowError
        ):
            pass

    return score


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

    except (
        ValueError,
        TypeError,
        OverflowError
    ):
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

        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.netloc)
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

    # Escape dynamic values for Telegram HTML
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

    successful_sends = 0

    for chat_id in CHAT_IDS:

        payload["chat_id"] = chat_id

        try:
            response = requests.post(
                url,
                json=payload,
                timeout=20
            )

            response.raise_for_status()

            successful_sends += 1

            log.info(
                "Telegram alert sent to %s",
                chat_id
            )

        except Exception as e:

            log.exception(
                "Telegram send failed for %s: %s",
                chat_id,
                e
            )

    if successful_sends == 0:
        raise RuntimeError(
            "Telegram alert failed for every destination"
        )

    return successful_sends

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

    candidates = []

    try:
        tokens = get_latest_tokens()

        log.info(
            "DexScreener returned %d token profiles",
            len(tokens)
        )

        # ----------------------------------------------------
        # DISCOVERY
        # ----------------------------------------------------

        for token in tokens:

            if len(candidates) >= MAX_CANDIDATES:
                break

            if not isinstance(token, dict):
                continue

            chain = token.get("chainId")
            address = token.get("tokenAddress")

            if not chain or not address:
                continue

            token_id = f"{chain}:{address}"

            # Already successfully processed
            if token_id in seen_set:
                continue

            # Duplicate within this API response
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

                    continue

                # Select the highest-liquidity pair
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
                    "Candidate analysis failed for %s: %s",
                    token_id,
                    e
                )

                continue

            # ------------------------------------------------
            # DISCOVERY SCORE
            # ------------------------------------------------

            score = calculate_discovery_score(pair)

            if score < MIN_DISCOVERY_SCORE:

                log.info(
                    "Rejected candidate: %s | score=%d",
                    token_id,
                    score
                )

                continue

            candidates.append({
                "token": token,
                "pair": pair,
                "token_id": token_id,
                "score": score
            })

            log.info(
                "Candidate accepted: %s | score=%d",
                token_id,
                score
            )

        # ----------------------------------------------------
        # RANK CANDIDATES
        # ----------------------------------------------------

        candidates.sort(
            key=lambda item: item["score"],
            reverse=True
        )

        log.info(
            "Qualified candidates: %d",
            len(candidates)
        )

        # ----------------------------------------------------
        # SEND TOP CANDIDATES
        # ----------------------------------------------------

        for candidate in candidates[:MAX_ALERTS_PER_RUN]:

            token = candidate["token"]
            pair = candidate["pair"]
            token_id = candidate["token_id"]
            score = candidate["score"]

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
                    "Alert sent: %s | score=%d",
                    token_id,
                    score
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
            "Run complete | alerts sent: %d | candidates: %d",
            sent,
            len(candidates)
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
