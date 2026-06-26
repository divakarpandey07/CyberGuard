"""
config.py – CyberGuard IDS v4 Configuration
Supports .env file — Copy .env.example to .env and fill values.
ALL FEATURES ARE FREE — No subscription required.
"""
import os, platform

# ── Load .env file if it exists ────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(_env_path):
        load_dotenv(_env_path)
        print(f"[config] ✅ Loaded .env from {_env_path}")
    else:
        print("[config] ℹ️  No .env file found — using defaults. Copy .env.example → .env to configure.")
except ImportError:
    pass  # python-dotenv not installed yet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

# ── Network ────────────────────────────────────────────────────────────────
INTERFACE      = os.environ.get("INTERFACE", None)
FLOW_TIMEOUT   = 30   # Reduced from 120 for faster live data
CAPTURE_FILTER = "ip or ip6"     # IPv6 included

# ── Dataset ────────────────────────────────────────────────────────────────
DATASET_DIR = os.path.join(ROOT_DIR, "dataset")
CICIDS_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

# ── ML ─────────────────────────────────────────────────────────────────────
MODEL_DIR             = os.path.join(BASE_DIR, "models")
CONFIDENCE_THRESHOLD  = 0.55
ANOMALY_CONTAMINATION = 0.05
ENSEMBLE_W_XGB        = 0.70
ENSEMBLE_W_ISO        = 0.30

# ── Auto-Blocking ──────────────────────────────────────────────────────────
AUTO_BLOCK_ENABLED = os.environ.get("AUTO_BLOCK_ENABLED", "false").lower() == "true"
BLOCK_THRESHOLD    = 3
BLOCK_DURATION     = 3600

def _get_local_ips():
    import socket
    ips = ["127.0.0.1", "::1", "0.0.0.0", "::"]
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if addr not in ips:
                ips.append(addr)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        addr = s.getsockname()[0]
        if addr not in ips:
            ips.append(addr)
        s.close()
    except Exception:
        pass
    return ips

WHITELIST_IPS = _get_local_ips()

# ── Logging / Export ───────────────────────────────────────────────────────
LOG_DIR          = os.path.join(ROOT_DIR, "logs")
PCAP_DIR         = os.path.join(ROOT_DIR, "pcap_exports")
MAX_LOG_SIZE_MB  = 10
LOG_BACKUP_COUNT = 5
ALERT_SOUND      = False

# ── Flask ──────────────────────────────────────────────────────────────────
HOST       = os.environ.get("HOST", "0.0.0.0")
PORT       = int(os.environ.get("PORT", "5000"))
SECRET_KEY = os.environ.get("CYBERGUARD_SECRET", "CyberGuard-2026")
DEBUG      = os.environ.get("DEBUG", "false").lower() == "true"
OS_PLATFORM = platform.system()

# ── Telegram Alerts (FREE — create bot via @BotFather) ────────────────────
# Full guide: SETUP_GUIDE.md → "Telegram Bot Setup"
TELEGRAM_ENABLED   = os.environ.get("TELEGRAM_ENABLED", "false").lower() == "true"
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")

# ── Email Alerts (FREE — Gmail App Password) ───────────────────────────────
# Full guide: SETUP_GUIDE.md → "Gmail Setup"
EMAIL_ENABLED   = os.environ.get("EMAIL_ENABLED", "false").lower() == "true"
EMAIL_SMTP_HOST = "smtp.gmail.com"
EMAIL_SMTP_PORT = 587
EMAIL_SENDER    = os.environ.get("ALERT_EMAIL_FROM", "")
EMAIL_PASSWORD  = os.environ.get("ALERT_EMAIL_PASS", "")
EMAIL_RECIPIENT = os.environ.get("ALERT_EMAIL_TO", "")

# ── Honeypot (FREE — pure Python sockets) ────────────────────────────────
HONEYPOT_ENABLED = True
HONEYPOT_PORTS   = [21, 22, 23, 3389, 8080, 1433, 3306]

# ── Behavioral Profiling (FREE — pure Python) ─────────────────────────────
BEHAVIOR_WINDOW_SEC = 300
BEHAVIOR_MAX_IPS    = 1000

# ── GeoIP (FREE — ip-api.com, no key needed, 45 req/min) ──────────────────
GEOIP_ENABLED    = True
GEOIP_CACHE_SIZE = 500

# ── Threat Intelligence (FREE — register at abuseipdb.com) ────────────────
# Free tier: 1000 checks/day. Guide: SETUP_GUIDE.md → "AbuseIPDB"
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_KEY", "")

# ── Autoencoder Zero-Day Detection (FREE — scikit-learn) ──────────────────
AUTOENCODER_ENABLED       = False  # Set to True if you want to detect zero-day anomalies (sensitive to local network differences)
AUTOENCODER_THRESHOLD_PCT = 95

# ── Isolation Forest Anomaly Detection ────────────────────────────────────
ANOMALY_DETECTION_ENABLED = False  # Set to True to enable anomaly overrides (sensitive to local network differences)

# ── Online Incremental Learning (FREE — pip install river) ────────────────
ONLINE_LEARNING_ENABLED = os.environ.get("ONLINE_LEARNING_ENABLED", "false").lower() == "true"

# ── CICIDS2017 Label Maps ──────────────────────────────────────────────────
CICIDS_LABEL_MAP = {
    "BENIGN": 0,
    "DoS Hulk": 1, "DoS GoldenEye": 1, "DoS slowloris": 1,
    "DoS Slowhttptest": 1, "DDoS": 1, "Heartbleed": 1,
    "PortScan": 2,
    "FTP-Patator": 3, "SSH-Patator": 3, "Infiltration": 3, "Bot": 3,
    "Web Attack \x96 Brute Force": 3, "Web Attack \x96 XSS": 3,
    "Web Attack \x96 Sql Injection": 3,
    "Web Attack \u2013 Brute Force": 3, "Web Attack \u2013 XSS": 3,
    "Web Attack \u2013 Sql Injection": 3,
}

ATTACK_LABELS = {
    0: "Normal",
    1: "DoS/DDoS",
    2: "PortScan",
    3: "Infiltration",
    4: "Anomaly",
    5: "Zero-Day",
    6: "DNS Attack",
}

ATTACK_COLORS = {
    "Normal":       "#10b981",
    "DoS/DDoS":     "#ef4444",
    "PortScan":     "#f59e0b",
    "Infiltration": "#8b5cf6",
    "Anomaly":      "#6b7280",
    "Zero-Day":     "#dc2626",
    "DNS Attack":   "#0ea5e9",
}

FEATURE_NAMES = [
    "flow_duration","total_fwd_packets","total_backward_packets",
    "total_length_fwd_packets","total_length_bwd_packets",
    "fwd_packet_length_max","fwd_packet_length_min","fwd_packet_length_mean","fwd_packet_length_std",
    "bwd_packet_length_max","bwd_packet_length_min","bwd_packet_length_mean","bwd_packet_length_std",
    "flow_bytes_s","flow_packets_s",
    "flow_iat_mean","flow_iat_std","flow_iat_max","flow_iat_min",
    "fwd_iat_total","fwd_iat_mean","fwd_iat_std","fwd_iat_max","fwd_iat_min",
    "bwd_iat_total","bwd_iat_mean","bwd_iat_std","bwd_iat_max","bwd_iat_min",
    "fwd_psh_flags","bwd_psh_flags","fwd_urg_flags","bwd_urg_flags",
    "fwd_header_length","bwd_header_length",
    "fwd_packets_s","bwd_packets_s",
    "min_packet_length","max_packet_length",
    "packet_length_mean","packet_length_std","packet_length_variance",
    "fin_flag_count","syn_flag_count","rst_flag_count","psh_flag_count",
    "ack_flag_count","urg_flag_count","cwe_flag_count","ece_flag_count",
    "down_up_ratio","average_packet_size","avg_fwd_segment_size","avg_bwd_segment_size",
    "fwd_header_length_1",
    "fwd_avg_bytes_bulk","fwd_avg_packets_bulk","fwd_avg_bulk_rate",
    "bwd_avg_bytes_bulk","bwd_avg_packets_bulk","bwd_avg_bulk_rate",
    "subflow_fwd_packets","subflow_fwd_bytes","subflow_bwd_packets","subflow_bwd_bytes",
    "init_win_bytes_forward","init_win_bytes_backward",
    "act_data_pkt_fwd","min_seg_size_forward",
    "active_mean","active_std","active_max","active_min",
    "idle_mean","idle_std","idle_max","idle_min",
]
