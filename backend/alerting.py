"""
alerting.py – Telegram + Email alert dispatcher
Both are completely FREE:
  Telegram : Create a bot via @BotFather (see config.py for steps)
  Email    : Gmail SMTP with App Password
Non-blocking: all sends happen in background threads.
Cooldown: same alert type won't spam (30 sec gap).
"""
import logging, threading, time, smtplib
from email.mime.text      import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Tuple

import config

logger = logging.getLogger("CyberGuard.Alerting")


def _fmt(cls: dict, feat: dict) -> str:
    return (
        f"\U0001f6a8 CyberGuard IDS v4 Alert\n"
        f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
        f"\U0001f534 Attack   : {cls.get('label', 'Unknown')}\n"
        f"\u26a1 Severity : {cls.get('severity', 'N/A')}\n"
        f"\U0001f4ca Confidence: {cls.get('confidence', 0)*100:.1f}%\n"
        f"\U0001f310 Source IP : {feat.get('_src_ip', '?')}\n"
        f"\U0001f3af Dest      : {feat.get('_dst_ip', '?')}:{feat.get('_dst_port', 0)}\n"
        f"\U0001f4a1 Action    : {cls.get('recommendation', 'N/A')}\n"
        f"\U0001f552 Time      : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
    )


class AlertManager:
    """Non-blocking, cooldown-aware alert dispatcher."""

    def __init__(self):
        self._queue   : List[Tuple[dict, dict]] = []
        self._lock    = threading.Lock()
        self._cooldown: dict = {}     # label → last_sent_epoch
        self._gap_sec = 30            # min seconds between same label
        self._thread  = threading.Thread(target=self._loop, daemon=True, name="AlertManager")
        self._thread.start()

    # ── Public API ─────────────────────────────────────────────────────────

    def send_alert(self, cls: dict, feat: dict) -> None:
        """Queue alert (returns immediately, sends in background)."""
        label = cls.get("label", "Unknown")
        now   = time.time()
        if now - self._cooldown.get(label, 0) < self._gap_sec:
            return
        self._cooldown[label] = now
        with self._lock:
            self._queue.append((cls, feat))

    def test_telegram(self) -> bool:
        """Send a test message to verify Telegram setup."""
        return self._telegram("🧪 CyberGuard test message — Telegram alerts are working!")

    def test_email(self) -> bool:
        """Send a test email."""
        return self._email({"label": "Test"}, "🧪 CyberGuard test email — alerts are working!")

    # ── Internal ──────────────────────────────────────────────────────────

    def _loop(self):
        while True:
            with self._lock:
                items = self._queue[:]
                self._queue.clear()
            for cls, feat in items:
                msg = _fmt(cls, feat)
                if config.TELEGRAM_ENABLED:
                    threading.Thread(target=self._telegram, args=(msg,), daemon=True).start()
                if config.EMAIL_ENABLED:
                    threading.Thread(target=self._email, args=(cls, msg), daemon=True).start()
            time.sleep(1)

    @staticmethod
    def _telegram(message: str) -> bool:
        token = config.TELEGRAM_BOT_TOKEN
        chat  = config.TELEGRAM_CHAT_ID
        if not token or not chat:
            logger.warning(
                "Telegram not configured.\n"
                "  Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in config.py or env."
            )
            return False
        try:
            import requests
            r = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat, "text": message},
                timeout=10,
            )
            if r.status_code == 200:
                logger.info("✅ Telegram alert sent")
                return True
            logger.warning("Telegram error %d: %s", r.status_code, r.text[:100])
        except Exception as e:
            logger.error("Telegram send failed: %s", e)
        return False

    @staticmethod
    def _email(cls: dict, body: str) -> bool:
        sender = config.EMAIL_SENDER
        passwd = config.EMAIL_PASSWORD
        recip  = config.EMAIL_RECIPIENT
        if not sender or not passwd or not recip:
            logger.warning(
                "Email not configured.\n"
                "  Set ALERT_EMAIL_FROM, ALERT_EMAIL_PASS, ALERT_EMAIL_TO in config.py or env."
            )
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"\U0001f6a8 CyberGuard: {cls.get('label','Attack')} Detected"
            msg["From"]    = sender
            msg["To"]      = recip
            html = f"<pre style='font-family:monospace'>{body}</pre>"
            msg.attach(MIMEText(body, "plain", "utf-8"))
            msg.attach(MIMEText(html,  "html",  "utf-8"))
            with smtplib.SMTP(config.EMAIL_SMTP_HOST, config.EMAIL_SMTP_PORT) as s:
                s.starttls()
                s.login(sender, passwd)
                s.sendmail(sender, recip, msg.as_string())
            logger.info("✅ Email alert sent to %s", recip)
            return True
        except Exception as e:
            logger.error("Email send failed: %s", e)
        return False
