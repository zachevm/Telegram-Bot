import asyncio
import csv
import html
import json
import logging
import os
import re
import xml.etree.ElementTree as ET
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

# Tracking files (committed back to the repo by the workflow, like seen.json)
ALERTS_FILE = "alerts.csv"      # every delivered alert + what its price did afterwards
REJECTED_FILE = "rejected.csv"  # tokens the filters rejected + what their price did afterwards
RUNS_FILE = "runs.csv"          # one row per run with the SUMMARY counts
PATHS_FILE = "alert_paths.csv"  # each alert's price every ~10 minutes for 24h (for testing exit rules)
MAX_PATH_ROWS = 40000
MAX_ALERT_ROWS = 5000
MAX_REJECTED_ROWS = 6000
MAX_RUN_ROWS = 5000
MAX_NEW_REJECTS_PER_RUN = 40    # cap on newly logged rejected tokens per run
MAX_TRACKING_CALLS = 40         # cap on DexScreener price lookups per run for tracking

# Chains. Only tokens on ALLOWED_CHAINS are sent, each labelled with its chain (e.g. "SOLANA CALL").
# Everything else that passes the filters is NOT sent; it is logged to rejected.csv with reason
# "other chain" or "tier B" and still tracked, so you can see what you skipped.
# CHAIN_MIN_LIQUIDITY_USD sets a higher liquidity floor for a chain; other chains use the global floor.
# MAX_ALERTS_PER_CHAIN_PER_RUN stops one busy chain (Solana) from using up all the slots in a run.
# Set TIERING_ENABLED = False to send every chain's tokens.
TIERING_ENABLED = True
ALLOWED_CHAINS = {"solana", "ethereum", "bsc", "base", "robinhood"}
CHAIN_MIN_LIQUIDITY_USD = {"robinhood": 33_000}
CHAIN_LABELS = {"solana": "SOLANA", "ethereum": "ETH", "bsc": "BSC", "base": "BASE", "robinhood": "ROBINHOOD"}
MAX_ALERTS_PER_CHAIN_PER_RUN = 2
MAX_PLAUSIBLE_MULTIPLE = 1000   # tracked prices above 1,000x the alert price are treated as bad data and ignored

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

def pair_age_hours(pair):
    created_at = pair.get("pairCreatedAt")
    if not created_at:
        return None
    try:
        created = datetime.fromtimestamp(created_at / 1000, tz=timezone.utc)
        return (datetime.now(timezone.utc) - created).total_seconds() / 3600
    except (ValueError, TypeError, OverflowError):
        return None

def chain_reject_reason(chain, pair):
    """None if the token may be sent; otherwise why it is held back (logged, not sent)."""
    chain = str(chain).lower()
    if chain not in ALLOWED_CHAINS:
        return "other chain"
    floor = CHAIN_MIN_LIQUIDITY_USD.get(chain)
    if floor is not None:
        try:
            liquidity = float((pair.get("liquidity") or {}).get("usd") or 0)
        except (ValueError, TypeError):
            return "tier B"
        if liquidity < floor:
            return "tier B"
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

def build_message(token, pair, tags=None):
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

    tag_lines = ""
    if tags and tags.get("topic"):
        tag_lines += f"🔥 <b>TRENDING TOPIC:</b> {html.escape(str(tags['topic']))}\n"
    if tags and tags.get("onchain"):
        tag_lines += "📈 <b>TRENDING ON-CHAIN</b>\n"

    message = (
        f"🚨 <b>{html.escape(CHAIN_LABELS.get(str(chain).lower(), str(chain).upper()))} CALL</b>\n{tag_lines}\n"
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
# TRACKING (alerts.csv, rejected.csv, runs.csv)
# ============================================================

ALERT_FIELDS = [
    "time", "token_id", "chain", "address", "symbol", "score", "price_usd",
    "liquidity_usd", "volume_24h", "market_cap", "age_hours", "buys_24h", "sells_24h",
    "change_1h", "change_24h", "price_1h", "price_6h", "price_24h", "max_price", "min_price", "tag",
]
REJECTED_FIELDS = [
    "time", "token_id", "chain", "address", "symbol", "reason", "score", "price_usd",
    "liquidity_usd", "volume_24h", "market_cap", "age_hours", "buys_24h", "sells_24h",
    "change_1h", "change_24h", "price_1h", "price_6h", "price_24h",
]
PATH_FIELDS = ["token_id", "minutes", "price"]
RUN_FIELDS = [
    "time", "profiles", "already_seen", "no_pair_data", "not_base_token", "lookup_errors",
    "rej_liquidity", "rej_trades", "rej_sells", "rej_no_age", "rej_age", "rej_price_change",
    "rej_bad_data", "low_score", "accepted", "alerts_sent", "group_sends", "dm_sends",
    "no_delivery", "session_failed", "tracking_calls", "tier_b",
    "trend_topics", "topic_tokens", "gecko_tokens", "tagged",
]

# Outcome checks: a price is recorded when a row is 1h, 6h and 24h old.
HORIZONS = (("price_1h", 1), ("price_6h", 6), ("price_24h", 24))
HORIZON_GRACE_HOURS = 2  # a missed check older than this is marked NA instead of filled late

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def hours_since(iso_time):
    try:
        t = datetime.fromisoformat(iso_time)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - t).total_seconds() / 3600
    except (ValueError, TypeError):
        return None

def read_csv_rows(path):
    """Rows as dicts. [] if the file doesn't exist yet. None if unreadable (so we never overwrite it)."""
    try:
        with open(path, newline="", encoding="utf-8") as f:
            return [
                {k: (v if v is not None else "") for k, v in row.items() if k is not None}
                for row in csv.DictReader(f)
            ]
    except FileNotFoundError:
        return []
    except Exception as e:
        log.exception("Could not read %s: %s", path, e)
        return None

def write_csv_rows(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", restval="")
        writer.writeheader()
        writer.writerows(rows)

def pair_metrics(pair):
    liquidity = (pair.get("liquidity") or {}).get("usd")
    volume = (pair.get("volume") or {}).get("h24")
    market_cap = pair.get("marketCap") or pair.get("fdv")
    tx = (pair.get("txns") or {}).get("h24") or {}
    change = pair.get("priceChange") or {}

    age_hours = ""
    created_at = pair.get("pairCreatedAt")
    if created_at:
        try:
            created = datetime.fromtimestamp(created_at / 1000, tz=timezone.utc)
            age_hours = round((datetime.now(timezone.utc) - created).total_seconds() / 3600, 2)
        except (ValueError, TypeError, OverflowError):
            pass

    return {
        "price_usd": pair.get("priceUsd") or "",
        "liquidity_usd": liquidity if liquidity is not None else "",
        "volume_24h": volume if volume is not None else "",
        "market_cap": market_cap if market_cap is not None else "",
        "age_hours": age_hours,
        "buys_24h": tx.get("buys", ""),
        "sells_24h": tx.get("sells", ""),
        "change_1h": change.get("h1", ""),
        "change_24h": change.get("h24", ""),
    }

def safe_score(pair):
    try:
        return calculate_discovery_score(pair)
    except Exception:
        return ""

def make_alert_row(token, pair, token_id, score, tag=""):
    row = {
        "time": now_iso(),
        "token_id": token_id,
        "chain": token.get("chainId", ""),
        "address": token.get("tokenAddress", ""),
        "symbol": (pair.get("baseToken") or {}).get("symbol", ""),
        "score": score,
        "tag": tag,
        "price_1h": "", "price_6h": "", "price_24h": "",
    }
    row.update(pair_metrics(pair))
    row["max_price"] = row["price_usd"]
    row["min_price"] = row["price_usd"]
    return row

def make_reject_row(token, pair, token_id, reason, score):
    row = {
        "time": now_iso(),
        "token_id": token_id,
        "chain": token.get("chainId", ""),
        "address": token.get("tokenAddress", ""),
        "symbol": (pair.get("baseToken") or {}).get("symbol", ""),
        "reason": reason,
        "score": score,
        "price_1h": "", "price_6h": "", "price_24h": "",
    }
    row.update(pair_metrics(pair))
    return row

def fetch_prices(wanted, max_calls=MAX_TRACKING_CALLS):
    """wanted: set of (chain, address). Returns ({(chain, address_lower): price}, calls_made).
    Looks tokens up in batches of up to 30 addresses per request."""
    by_chain = {}
    for chain, address in wanted:
        by_chain.setdefault(chain, []).append(address)

    prices = {}
    calls = 0
    for chain, addresses in by_chain.items():
        for i in range(0, len(addresses), 30):
            if calls >= max_calls:
                log.warning("Tracking lookup cap reached (%d calls); the rest waits for the next run", max_calls)
                return prices, calls
            chunk = addresses[i:i + 30]
            calls += 1
            try:
                response = session.get(f"{TOKEN_URL}/{chain}/{','.join(chunk)}", timeout=20)
                response.raise_for_status()
                data = response.json()
            except Exception as e:
                log.warning("Tracking lookup failed for %s: %s", chain, e)
                continue
            if not isinstance(data, list):
                continue

            wanted_lower = {a.lower() for a in chunk}
            best = {}  # address_lower -> (liquidity, price)
            for p in data:
                if not isinstance(p, dict):
                    continue
                base = str((p.get("baseToken") or {}).get("address") or "").lower()
                if base not in wanted_lower:
                    continue
                try:
                    liq = float((p.get("liquidity") or {}).get("usd") or 0)
                    price = float(p.get("priceUsd"))
                except (ValueError, TypeError):
                    continue
                if base not in best or liq > best[base][0]:
                    best[base] = (liq, price)
            for base, (_, price) in best.items():
                prices[(chain, base)] = price
    return prices, calls

def horizon_state(row):
    """(age_hours, columns due now, columns whose window was missed)."""
    age = hours_since(row.get("time"))
    due, expired = [], []
    if age is None:
        return None, due, expired
    for col, hrs in HORIZONS:
        if row.get(col):
            continue
        if age >= hrs + HORIZON_GRACE_HOURS:
            expired.append(col)
        elif age >= hrs:
            due.append(col)
    return age, due, expired

def update_outcomes(alert_rows, rejected_rows, path_rows=None):
    """Fill in 1h/6h/24h prices. Alerts also get max/min price while they are under 24h old.
    Returns (lookup_calls, rows_updated)."""
    plans = []
    wanted = set()
    for rows, track_range in ((alert_rows, True), (rejected_rows, False)):
        for row in rows:
            age, due, expired = horizon_state(row)
            if age is None:
                continue
            for col in expired:
                row[col] = "NA"
            watching = track_range and age < 24 + HORIZON_GRACE_HOURS
            if due or watching:
                chain, address = row.get("chain", ""), row.get("address", "")
                if chain and address:
                    plans.append((row, due, watching, age))
                    wanted.add((chain, address))
    if not wanted:
        return 0, 0

    prices, calls = fetch_prices(wanted)
    updated = 0
    for row, due, watching, age in plans:
        price = prices.get((row["chain"], str(row["address"]).lower()))
        if price is None:
            continue  # token not returned; a due check is retried next run until its window passes
        try:
            entry = float(row.get("price_usd") or 0)
        except ValueError:
            entry = 0
        if price <= 0 or (entry > 0 and price / entry > MAX_PLAUSIBLE_MULTIPLE):
            log.warning("Ignoring implausible price for %s: %s (alert price %s)",
                        row.get("token_id"), price, row.get("price_usd"))
            continue  # treated as bad data; the check expires to NA if it never gets a sane price
        for col in due:
            row[col] = f"{price:.12g}"
        if watching:
            try:
                hi = float(row.get("max_price") or price)
                lo = float(row.get("min_price") or price)
            except ValueError:
                hi = lo = price
            row["max_price"] = f"{max(hi, price):.12g}"
            row["min_price"] = f"{min(lo, price):.12g}"
            if path_rows is not None:
                path_rows.append({"token_id": row.get("token_id", ""), "minutes": int(round(age * 60)),
                                  "price": f"{price:.12g}"})
        updated += 1
    return calls, updated

def save_tracking(new_alerts, new_rejects, run_row):
    """Update outcome prices on logged rows, then append this run's rows. Never raises."""
    try:
        alert_rows = read_csv_rows(ALERTS_FILE)
        rejected_rows = read_csv_rows(REJECTED_FILE)
        run_rows = read_csv_rows(RUNS_FILE)
        path_rows = read_csv_rows(PATHS_FILE)
        new_paths = []

        calls = updated = 0
        if alert_rows is not None and rejected_rows is not None:
            try:
                calls, updated = update_outcomes(alert_rows, rejected_rows, new_paths)
            except Exception as e:
                log.exception("Outcome update failed: %s", e)
        run_row["tracking_calls"] = calls

        if alert_rows is not None:
            alert_rows.extend(new_alerts)
            write_csv_rows(ALERTS_FILE, ALERT_FIELDS, alert_rows[-MAX_ALERT_ROWS:])
        if rejected_rows is not None:
            rejected_rows.extend(new_rejects)
            write_csv_rows(REJECTED_FILE, REJECTED_FIELDS, rejected_rows[-MAX_REJECTED_ROWS:])
        for row in new_alerts:  # minute 0 = the alert price itself
            new_paths.append({"token_id": row["token_id"], "minutes": 0, "price": row["price_usd"]})
        if path_rows is not None:
            path_rows.extend(new_paths)
            write_csv_rows(PATHS_FILE, PATH_FIELDS, path_rows[-MAX_PATH_ROWS:])
        if run_rows is not None:
            run_rows.append(run_row)
            write_csv_rows(RUNS_FILE, RUN_FIELDS, run_rows[-MAX_RUN_ROWS:])

        log.info("Tracking | price lookups: %d | rows updated: %d | new alerts logged: %d | new rejects logged: %d",
                 calls, updated, len(new_alerts), len(new_rejects))
    except Exception as e:
        log.exception("Tracking update failed (alerts are unaffected): %s", e)

# ============================================================
# TRENDING TAGS (free sources only)
#   1. Topic match: Google's trending searches -> DexScreener search -> best token per topic.
#   2. On-chain trending: tokens on GeckoTerminal's trending-pools lists.
# These only add a label to an alert (and, for topic matches, surface tokens the profile feed
# missed). Any failure here is logged and ignored: it never stops normal alerts.
# ============================================================

TRENDS_ENABLED = True
TREND_FEED_URLS = ["https://trends.google.com/trending/rss?geo=US"]
TREND_MAX_TOPICS = 20            # topics checked per run
TREND_MAX_TOPIC_TOKENS = 3       # most topic-matched tokens added per run
TOPIC_MAX_PAIR_AGE_HOURS = 72    # a token named after an event must be a recent launch
SEARCH_URL = "https://api.dexscreener.com/latest/dex/search"
GECKO_URL = "https://api.geckoterminal.com/api/v2"
GECKO_NETWORKS = ["solana", "eth", "bsc", "base"]
TREND_STOPWORDS = {"the", "and", "for", "with", "from", "that", "this", "vs", "live", "news", "today", "score",
                   "game", "news", "update", "updates", "highlights", "weather", "near", "what", "when"}

def norm_words(text):
    return re.sub(r"[^a-z0-9 ]+", " ", str(text or "").lower()).split()

def fetch_trending_topics():
    topics, seen_topics = [], set()
    for url in TREND_FEED_URLS:
        try:
            r = session.get(url, timeout=20)
            r.raise_for_status()
            root = ET.fromstring(r.content)
        except Exception as e:
            log.warning("Trending topics feed failed (%s): %s", url, e)
            continue
        for item in root.iter("item"):
            words = norm_words(item.findtext("title"))
            phrase = " ".join(words)
            if len("".join(words)) < 4 or phrase in seen_topics:
                continue
            seen_topics.add(phrase)
            topics.append(phrase)
    return topics[:TREND_MAX_TOPICS]

def name_matches_topic(topic_words, name, symbol):
    topic_flat = "".join(topic_words)
    name_flat = "".join(norm_words(name))
    sym_flat = "".join(norm_words(symbol))
    if len(topic_flat) >= 4 and (topic_flat in name_flat or topic_flat in sym_flat):
        return True
    sig = [w for w in topic_words if len(w) >= 4 and w not in TREND_STOPWORDS]
    return len(sig) >= 2 and all(w in name_flat for w in sig)

def find_topic_tokens(topics):
    """For each topic, search DexScreener and keep the single best matching token
    (highest liquidity, then volume) on an allowed chain that launched recently."""
    found, used = [], set()
    for topic in topics:
        if len(found) >= TREND_MAX_TOPIC_TOKENS:
            break
        words = topic.split()
        try:
            r = session.get(SEARCH_URL, params={"q": topic}, timeout=20)
            r.raise_for_status()
            pairs = r.json().get("pairs") or []
        except Exception as e:
            log.warning("Topic search failed for %r: %s", topic, e)
            continue
        best = None
        for pr in pairs:
            if not isinstance(pr, dict):
                continue
            if str(pr.get("chainId", "")).lower() not in ALLOWED_CHAINS:
                continue
            base = pr.get("baseToken") or {}
            if not name_matches_topic(words, base.get("name"), base.get("symbol")):
                continue
            age = pair_age_hours(pr)
            if age is None or age > TOPIC_MAX_PAIR_AGE_HOURS:
                continue
            try:
                key = (float((pr.get("liquidity") or {}).get("usd") or 0),
                       float((pr.get("volume") or {}).get("h24") or 0))
            except (ValueError, TypeError):
                continue
            if best is None or key > best[0]:
                best = (key, pr)
        if best:
            pr = best[1]
            addr = (pr.get("baseToken") or {}).get("address")
            ident = (str(pr.get("chainId")), str(addr).lower())
            if addr and ident not in used:
                used.add(ident)
                found.append(({"chainId": pr["chainId"], "tokenAddress": addr, "description": "",
                               "links": [], "url": pr.get("url", "")}, topic))
    return found

def fetch_gecko_trending():
    """Addresses (lower-case) of base tokens in GeckoTerminal's trending pools."""
    addrs = set()
    urls = [f"{GECKO_URL}/networks/trending_pools"] + [f"{GECKO_URL}/networks/{n}/trending_pools" for n in GECKO_NETWORKS]
    for url in urls:
        try:
            r = session.get(url, headers={"accept": "application/json"}, timeout=20)
            r.raise_for_status()
            data = r.json().get("data") or []
        except Exception as e:
            log.warning("GeckoTerminal trending failed (%s): %s", url, e)
            continue
        for pool in data:
            try:
                tid = str(pool["relationships"]["base_token"]["data"]["id"])
            except (KeyError, TypeError):
                continue
            if "_" in tid:
                addrs.add(tid.split("_", 1)[1].lower())
    return addrs

def tags_to_text(tags):
    if not tags:
        return ""
    parts = []
    if tags.get("topic"):
        parts.append(f"topic: {tags['topic']}")
    if tags.get("onchain"):
        parts.append("onchain")
    return " + ".join(parts)

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

    # Tracking collectors (written to CSV in the finally block)
    new_alerts = []
    new_rejects = []
    existing_rejected = read_csv_rows(REJECTED_FILE) or []
    rejected_keys = {(r.get("token_id"), r.get("reason")) for r in existing_rejected}

    def log_reject(token, pair, token_id, reason, score=None):
        # Log each (token, reason) once, so the same dead token isn't re-logged every run.
        if (token_id, reason) in rejected_keys or len(new_rejects) >= MAX_NEW_REJECTS_PER_RUN:
            return
        rejected_keys.add((token_id, reason))
        new_rejects.append(make_reject_row(
            token, pair, token_id, reason, safe_score(pair) if score is None else score
        ))

    try:
        tokens = get_latest_tokens()
        log.info("DexScreener returned %d token profiles", len(tokens))
        stats["profiles"] = len(tokens)

        # Trending tags: free sources, failures ignored
        tag_map, gecko_set = {}, set()
        if TRENDS_ENABLED:
            try:
                topics = fetch_trending_topics()
                stats["trend topics"] = len(topics)
                topic_tokens = find_topic_tokens(topics)
                for tok, topic in topic_tokens:
                    tag_map[f"{tok['chainId']}:{tok['tokenAddress']}"] = topic
                tokens = [tok for tok, _ in topic_tokens] + list(tokens)
                stats["topic tokens"] = len(topic_tokens)
                for tok, topic in topic_tokens:
                    log.info("Topic match: %r -> %s:%s", topic, tok["chainId"], tok["tokenAddress"])
            except Exception as e:
                log.warning("Topic matching failed: %s", e)
            try:
                gecko_set = fetch_gecko_trending()
                stats["gecko trending"] = len(gecko_set)
            except Exception as e:
                log.warning("GeckoTerminal tagging failed: %s", e)

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
                log_reject(token, pair, token_id, reason)
                continue

            score = calculate_discovery_score(pair)
            if score < MIN_DISCOVERY_SCORE:
                stats["low score"] += 1
                log_reject(token, pair, token_id, "low score", score)
                continue

            hold_reason = chain_reject_reason(chain, pair) if TIERING_ENABLED else None
            if hold_reason:
                stats["tier B"] += 1
                log.info("Held back (%s), logged not sent: %s | score=%d", hold_reason, token_id, score)
                log_reject(token, pair, token_id, hold_reason, score)
                continue

            candidates.append({
                "token": token,
                "pair": pair,
                "token_id": token_id,
                "score": score,
                "tags": {"topic": tag_map.get(token_id), "onchain": str(address).lower() in gecko_set},
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
            chosen, per_chain = [], Counter()
            for cand in candidates:
                ch = str(cand["token"].get("chainId", "")).lower()
                if per_chain[ch] >= MAX_ALERTS_PER_CHAIN_PER_RUN:
                    stats["chain cap"] += 1
                    continue  # not marked seen, so it is reconsidered next run
                chosen.append(cand)
                per_chain[ch] += 1
                if len(chosen) >= MAX_ALERTS_PER_RUN:
                    break
            for alert_index, candidate in enumerate(chosen):
                # Pace consecutive scanner alerts; the first alert is sent immediately.
                if alert_index > 0 and ALERT_DELAY_SECONDS > 0:
                    log.info("Waiting %s seconds before the next alert", ALERT_DELAY_SECONDS)
                    await asyncio.sleep(ALERT_DELAY_SECONDS)

                token = candidate["token"]
                pair = candidate["pair"]
                token_id = candidate["token_id"]
                score = candidate["score"]

                try:
                    message = build_message(token, pair, candidate.get("tags"))

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
                        tag_str = tags_to_text(candidate.get("tags"))
                        if tag_str:
                            stats["tagged"] += 1
                        new_alerts.append(make_alert_row(token, pair, token_id, score, tag_str))
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
            "lookup errors: %d | hard-filter rejects: [%s] | low score: %d | tier B: %d | accepted (tier A): %d | trend topics: %d | topic tokens: %d | gecko trending: %d | tagged: %d | "
            "group sends: %d | dm sends: %d | no delivery: %d",
            stats["profiles"], stats["already seen"], stats["no pair data"], stats["not base token"],
            stats["lookup error"], rejected, stats["low score"], stats["tier B"], len(candidates),
            stats["trend topics"], stats["topic tokens"], stats["gecko trending"], stats["tagged"],
            stats["group sends"], stats["dm sends"], stats["no delivery"],
        )
        log.info("Run complete | alerts sent: %d | candidates: %d", sent, len(candidates))

        run_row = {
            "time": now_iso(),
            "profiles": stats["profiles"],
            "already_seen": stats["already seen"],
            "no_pair_data": stats["no pair data"],
            "not_base_token": stats["not base token"],
            "lookup_errors": stats["lookup error"],
            "rej_liquidity": stats["rejected: liquidity"],
            "rej_trades": stats["rejected: trades"],
            "rej_sells": stats["rejected: sells"],
            "rej_no_age": stats["rejected: no age"],
            "rej_age": stats["rejected: age"],
            "rej_price_change": stats["rejected: price change"],
            "rej_bad_data": stats["rejected: bad data"],
            "low_score": stats["low score"],
            "accepted": len(candidates),
            "alerts_sent": sent,
            "group_sends": stats["group sends"],
            "dm_sends": stats["dm sends"],
            "no_delivery": stats["no delivery"],
            "session_failed": int(session_failed),
            "tier_b": stats["tier B"],
            "trend_topics": stats["trend topics"],
            "topic_tokens": stats["topic tokens"],
            "gecko_tokens": stats["gecko trending"],
            "tagged": stats["tagged"],
        }
        save_tracking(new_alerts, new_rejects, run_row)

    # Make a dead session visible: the run shows red in Actions instead of looking healthy.
    if session_failed:
        raise SystemExit(1)

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    asyncio.run(main())
