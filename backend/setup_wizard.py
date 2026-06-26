"""
setup_wizard.py – CyberGuard IDS v4 Interactive Setup
Run this ONCE to configure your .env file step by step.

Usage: python backend/setup_wizard.py
"""
import os, sys, json

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(ROOT_DIR, ".env")
EXAMPLE_PATH = os.path.join(ROOT_DIR, ".env.example")

GREEN = "\033[92m"
CYAN  = "\033[96m"
YELLOW= "\033[93m"
RED   = "\033[91m"
BOLD  = "\033[1m"
RESET = "\033[0m"

def p(msg, color=RESET): print(f"{color}{msg}{RESET}")

def ask(prompt, default="", secret=False):
    display = f"[{default}]" if default else "[leave empty to skip]"
    p(f"\n  {prompt} {display}: ", CYAN)
    try:
        if secret:
            import getpass
            val = getpass.getpass("  → ")
        else:
            val = input("  → ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return val if val else default

def ask_bool(prompt, default=False):
    d = "y/N" if not default else "Y/n"
    p(f"\n  {prompt} ({d}): ", CYAN)
    try:
        val = input("  → ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if val in ("y", "yes"): return True
    if val in ("n", "no"):  return False
    return default

def test_telegram(token, chat_id):
    try:
        import requests
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": "🛡️ <b>CyberGuard IDS v4</b> — Telegram setup successful! ✅",
                "parse_mode": "HTML"
            },
            timeout=10
        )
        return r.status_code == 200, r.text[:200]
    except Exception as e:
        return False, str(e)

def main():
    p("\n" + "="*60, BOLD)
    p("  🛡️  CyberGuard IDS v4 — Setup Wizard", BOLD)
    p("="*60 + "\n", BOLD)
    p("  This wizard will create your .env configuration file.")
    p("  Press Enter to skip any optional step.\n")

    config = {}

    # ── Telegram ────────────────────────────────────────────────────────
    p("\n━━━ 📡 TELEGRAM ALERTS (FREE) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━", YELLOW)
    p("  How to get your Bot Token:")
    p("  1. Open Telegram → Search @BotFather → Send /newbot")
    p("  2. Follow steps → Bot name → Username (must end in 'bot')")
    p("  3. Copy the token it gives you (like: 7123456789:AAF-abc...)")
    p("\n  How to get your Chat ID:")
    p("  1. Send any message to your new bot")
    p("  2. Open this URL in browser (replace YOUR_TOKEN):")
    p("     https://api.telegram.org/botYOUR_TOKEN/getUpdates")
    p("  3. Look for 'chat': {'id': 123456789} — that number is your Chat ID")
    p("  4. If empty: send /start to bot first, then refresh URL")

    tg_token = ask("Telegram Bot Token", secret=True)
    tg_chat  = ""
    tg_ok    = False

    if tg_token:
        tg_chat = ask("Telegram Chat ID")
        if tg_chat:
            p("\n  Testing Telegram... ", CYAN)
            ok, msg = test_telegram(tg_token, tg_chat)
            if ok:
                p("  ✅ Telegram works! Check your Telegram for a test message.", GREEN)
                tg_ok = True
            else:
                p(f"  ❌ Telegram test failed: {msg}", RED)
                p("     Double check your token and chat_id.", YELLOW)
                tg_ok = ask_bool("  Save Telegram config anyway?", False)
        config["TELEGRAM_ENABLED"] = "true" if (tg_token and tg_chat and tg_ok) else "false"
        config["TELEGRAM_BOT_TOKEN"] = tg_token
        config["TELEGRAM_CHAT_ID"]   = tg_chat

    # ── Email ───────────────────────────────────────────────────────────
    p("\n━━━ 📧 EMAIL ALERTS via GMAIL (FREE) ━━━━━━━━━━━━━━━━━━━━━━", YELLOW)
    p("  How to get Gmail App Password:")
    p("  1. Go to: https://myaccount.google.com/security")
    p("  2. Enable 2-Step Verification (if not already)")
    p("  3. Search 'App passwords' in Google Account")
    p("  4. Select 'Mail' → 'Other device' → type 'CyberGuard'")
    p("  5. Copy the 16-character password shown (like: abcd efgh ijkl mnop)")
    p("  NOTE: This is NOT your Gmail login password — it's a special app password")

    email_from = ask("Your Gmail address (sender)")
    email_pass = ""
    email_to   = ""
    if email_from:
        email_pass = ask("Gmail App Password (16 chars)", secret=True)
        email_to   = ask("Alert recipient email address")
        config["EMAIL_ENABLED"]    = "true" if (email_from and email_pass and email_to) else "false"
        config["ALERT_EMAIL_FROM"] = email_from
        config["ALERT_EMAIL_PASS"] = email_pass
        config["ALERT_EMAIL_TO"]   = email_to

    # ── AbuseIPDB ───────────────────────────────────────────────────────
    p("\n━━━ 🔍 ABUSEIPDB THREAT INTEL (FREE, 1000 checks/day) ━━━━━━", YELLOW)
    p("  How to get free API key:")
    p("  1. Go to: https://www.abuseipdb.com/register")
    p("  2. Register with email → Verify email")
    p("  3. Go to: https://www.abuseipdb.com/account/api")
    p("  4. Click 'Create Key' → Copy the key")
    p("  Limit: 1000 IP checks/day on free tier (more than enough)")

    abuse_key = ask("AbuseIPDB API Key", secret=True)
    if abuse_key:
        config["ABUSEIPDB_KEY"] = abuse_key

    # ── Optional features ───────────────────────────────────────────────
    p("\n━━━ ⚙️  OTHER SETTINGS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", YELLOW)
    auto_block = ask_bool("Enable Auto IP Blocking? (blocks attacking IPs via iptables)", False)
    config["AUTO_BLOCK_ENABLED"] = "true" if auto_block else "false"

    # ── Write .env ──────────────────────────────────────────────────────
    p("\n━━━ 💾 SAVING CONFIGURATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", YELLOW)

    env_content = "# CyberGuard IDS v4 — Auto-generated by setup_wizard.py\n\n"
    for key, val in config.items():
        env_content += f"{key}={val}\n"

    with open(ENV_PATH, "w") as f:
        f.write(env_content)

    p(f"\n  ✅ Configuration saved to: {ENV_PATH}", GREEN)

    # ── Summary ─────────────────────────────────────────────────────────
    p("\n" + "="*60, BOLD)
    p("  📋 SETUP SUMMARY", BOLD)
    p("="*60, BOLD)
    p(f"  Telegram Alerts : {'✅ ON' if config.get('TELEGRAM_ENABLED') == 'true' else '❌ OFF'}")
    p(f"  Email Alerts    : {'✅ ON' if config.get('EMAIL_ENABLED') == 'true' else '❌ OFF'}")
    p(f"  AbuseIPDB Intel : {'✅ ON' if config.get('ABUSEIPDB_KEY') else '❌ OFF'}")
    p(f"  Auto IP Block   : {'✅ ON' if config.get('AUTO_BLOCK_ENABLED') == 'true' else '❌ OFF'}")

    p("\n━━━ NEXT STEPS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", YELLOW)
    p("  1. Install dependencies:  pip install -r requirements.txt")
    p("  2. Train models:          python backend/train.py --fast")
    p("  3. Start server:          python backend/app.py  (or sudo for live capture)")
    p("  4. Open browser:          http://localhost:5000")
    p("  5. Test alerts:           Dashboard → Settings tab → Test Telegram/Email\n")

if __name__ == "__main__":
    main()
