import json
import os
from datetime import datetime, timezone

import requests

BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]

PROFILE_URL = "https://api.dexscreener.com/token-profiles/latest/v1"
TOKEN_URL = "https://api.dexscreener.com/tokens/v1"

SEEN_FILE = "seen.json"
BLACKLIST_FILE = "blacklist.json"

MAX_PER_RUN = 10


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def get_latest_tokens():
    response = requests.get(PROFILE_URL, timeout=15)
    response.raise_for_status()

    data = response.json()

    return [data] if isinstance(data, dict) else data


def get_token_pairs(chain, address):
    url = f"{TOKEN_URL}/{chain}/{address}"

    response = requests.get(url, timeout=15)
    response.raise_for_status()

    data = response.json()

    return data if isinstance(data, list) else []


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
        seconds = int((now - created).total_seconds())

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


def build_message(token, pair):
    chain = token.get("chainId", "Unknown")
    address = token.get("tokenAddress", "Unknown")

    name = pair.get("baseToken", {}).get("name", "Unknown")
    symbol = pair.get("baseToken", {}).get("symbol", "???")

    dex = pair.get("dexId", "Unknown")
    dex_url = pair.get("url") or token.get("url", "")

    price = pair.get("priceUsd")
    liquidity = pair.get("liquidity", {}).get("usd")
    volume = pair.get("volume", {}).get("h24")
    market_cap = pair.get("marketCap") or pair.get("fdv")

    transactions = pair.get("txns", {}).get("h24", {})
    buys = transactions.get("buys", 0)
    sells = transactions.get("sells", 0)

    price_change = pair.get("priceChange", {}).get("h24")

    age = format_age(pair.get("pairCreatedAt"))

    description = token.get("description") or ""

    icon = token.get("icon")

    links = token.get("links") or []

    websites = []
    socials = []

    for link in links:
        label = link.get("label", "")
        url = link.get("url", "")

        if not url:
            continue

        if label:
            websites.append(f"🌐 {label}: {url}")
        else:
            websites.append(f"🔗 {url}")

    if price_change is not None:
        try:
            change = float(price_change)
            change_text = f"{change:+.2f}%"
        except (ValueError, TypeError):
            change_text = "N/A"
    else:
        change_text = "N/A"

    message = (
        f"🚨 <b>NEW TOKEN DETECTED</b>\n\n"

        f"🪙 <b>{name}</b>  <code>${symbol}</code>\n\n"

        f"⛓ <b>Chain:</b> {chain}\n"
        f"🏪 <b>DEX:</b> {dex}\n"
        f"⏱ <b>Pair Age:</b> {age}\n\n"

        f"💵 <b>Price:</b> {format_number(price)}\n"
        f"💧 <b>Liquidity:</b> {format_number(liquidity)}\n"
        f"📊 <b>24h Volume:</b> {format_number(volume)}\n"
        f"💰 <b>Market Cap:</b> {format_number(market_cap)}\n"
        f"📈 <b>24h Change:</b> {change_text}\n\n"

        f"🟢 <b>Buys:</b> {buys}\n"
        f"🔴 <b>Sells:</b> {sells}\n\n"

        f"📜 <b>Contract</b>\n"
        f"<code>{address}</code>\n\n"
    )

    if description:
        clean_description = description[:500]
        message += f"📝 <b>About:</b>\n{clean_description}\n\n"

    message += "⚠️ <b>Security:</b> Not analysed yet\n"

    if icon:
        message += f"\n🖼 Token image: {icon}"

    return message, dex_url, icon


def send_telegram(text, dex_url, image_url=None):
    keyboard = {
        "inline_keyboard": [
            [
                {
                    "text": "📊 DexScreener",
                    "url": dex_url
                }
            ]
        ]
    }

    if image_url:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendPhoto"

        payload = {
            "chat_id": CHAT_ID,
            "photo": image_url,
            "caption": text[:1024],
            "parse_mode": "HTML",
            "reply_markup": json.dumps(keyboard)
        }

        response = requests.post(
            url,
            json=payload,
            timeout=20
        )

        # If Telegram rejects the image URL, fall back to text.
        if response.ok:
            return

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "reply_markup": keyboard
    }

    response = requests.post(
        url,
        json=payload,
        timeout=20
    )

    response.raise_for_status()


def main():
    seen = load_json(SEEN_FILE)
    seen_set = set(seen)

    blacklist = {
        address.lower()
        for address in load_json(BLACKLIST_FILE)
    }

    sent = 0

    tokens = get_latest_tokens()

    for token in tokens:

        if sent >= MAX_PER_RUN:
            break

        chain = token.get("chainId")
        address = token.get("tokenAddress")

        if not chain or not address:
            continue

        token_id = f"{chain}:{address}"

        if token_id in seen_set:
            continue

        # Mark it as seen even if later analysis fails.
        seen_set.add(token_id)
        seen.append(token_id)

        if address.lower() in blacklist:
            continue

        try:
            pairs = get_token_pairs(chain, address)

            if not pairs:
                print(f"No pair data: {chain}:{address}")
                continue

            # Pick the pair with the highest liquidity.
            pair = max(
                pairs,
                key=lambda p: float(
                    p.get("liquidity", {}).get("usd") or 0
                )
            )

            message, dex_url, image_url = build_message(
                token,
                pair
            )

            send_telegram(
                message,
                dex_url,
                image_url
            )

            sent += 1

            print(
                f"Sent: {chain} / "
                f"{pair.get('baseToken', {}).get('symbol', '???')}"
            )

        except Exception as e:
            print(
                f"Error processing "
                f"{chain}:{address}: {e}"
            )

    save_json(
        SEEN_FILE,
        seen[-1000:]
    )

    print(f"Sent {sent} alerts")


if __name__ == "__main__":
    main()
