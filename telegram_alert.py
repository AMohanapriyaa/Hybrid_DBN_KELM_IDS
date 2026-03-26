import os
import requests
from dotenv import load_dotenv

# Load variables from .env
load_dotenv()

# ── Configuration ──────────────────────────────────────────────
# Fetch from environment variables; defaults to previous values if not found (optional)
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8656656137:AAH5X-nTnA2Z5AOHf5w__THfhP1TdfRl4rE")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "5723668939")
# ──────────────────────────────────────────────────────────────

def send_telegram_alert(message):
    """
    Sends an alert message to a Telegram chat via a bot.

    Parameters
    ----------
    message : str
        The formatted alert message to send.

    Returns
    -------
    bool
        True if successful, False otherwise.
    """
    if not BOT_TOKEN or not CHAT_ID:
        print("[Telegram] Bot token or Chat ID not configured. Skipping alert.")
        return False

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }

    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        print("[Telegram] 📲 Alert sent successfully!")
        return True
    except requests.exceptions.RequestException as e:
        print(f"[Telegram] Failed to send alert: {e}")
        return False

if __name__ == "__main__":
    # Small test script
    print("Testing Telegram Alerts...")
    test_message = (
        "⚠️ INTRUSION DETECTED\n\n"
        "Attack Type : ICMP Ping Flood\n"
        "Attacker IP : 192.168.1.100\n"
        "Target IP : 192.168.1.1\n"
        "Protocol : ICMP\n"
        "Risk Level : High\n"
        "Time : 2026-03-11 12:00:00"
    )
    success = send_telegram_alert(test_message)
    if success:
        print("Test passed! Check your Telegram app.")
    else:
        print("Test failed. Please check your BOT_TOKEN and CHAT_ID.")
