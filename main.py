import json
import os

import requests

BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]

DEX_URL = "https://api.dexscreener.com/token-profiles/latest/v1"
SEEN_FILE = "seen.json"
BLACKLIST_FILE = "blacklist.json"
MAX_PER_RUN = 10


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def get_latest_tokens():
    r = requests.get(DEX_URL, timeout=15)
    r.raise_for_status()
    data = r.json()
    return [data] if isinstance(data, dict) else data


def send_telegram(text):
    r = requests.post(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        json={"chat_id": CHAT_ID, "text": text, "disable_web_page_preview": True},
        timeout=15,
    )
    r.raise_for_status()


def main():
    seen = load_json(SEEN_FILE)
    blacklist = {a.lower() for a in load_json(BLACKLIST_FILE)}
    sent = 0

    for token in get_latest_tokens():
        chain = token.get("chainId", "unknown")
        address = token.get("tokenAddress", "")
        token_id = f"{chain}:{address}"

        if not address or token_id in seen:
            continue
        seen.append(token_id)

        if address.lower() in blacklist:
            continue
        if sent >= MAX_PER_RUN:
            continue

        desc = token.get("description") or "No description"
        send_telegram(
            f"New token profile\n\nChain: {chain}\n"
            f"Description: {desc}\n\nContract:\n{address}\n\n"
            f"{token.get('url', '')}"
        )
        sent += 1

    with open(SEEN_FILE, "w") as f:
        json.dump(seen[-500:], f)
    print(f"Sent {sent} alerts")


if __name__ == "__main__":
    main()
