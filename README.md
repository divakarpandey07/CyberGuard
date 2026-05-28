# 🛡️ CyberGuard IDS v4
### Real-time Network Intrusion Detection System
**100% Free — No subscriptions, No API keys required (optional extras only)**

---

## 🆕 What's New in v3

| Feature | Status | Cost |
|---|---|---|
| 🌍 GeoIP Map (Leaflet + ip-api.com) | ✅ Active | FREE |
| 🍯 Honeypot (7 fake service ports) | ✅ Active | FREE |
| ⚡ Zero-Day Autoencoder | ✅ Active | FREE |
| 🧠 Behavioral Profiling per IP | ✅ Active | FREE |
| 📡 Telegram Alerts | ✅ Ready (config needed) | FREE |
| 📧 Email Alerts (Gmail) | ✅ Ready (config needed) | FREE |
| 🌐 DNS Attack Detection | ✅ Active | FREE |
| 🔒 Threat Intel (AbuseIPDB) | ✅ Ready (optional key) | FREE tier |
| 📦 PCAP Export (Scapy) | ✅ Active | FREE |
| 🌱 Online/Incremental Learning | ✅ Ready (pip install river) | FREE |
| 🐳 Docker Support | ✅ Active | FREE |
| 🔵 IPv6 Support | ✅ Active | FREE |

---

## ⚡ Quick Start (5 Steps)

### Step 1 — Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2 — Download CICIDS2017 Dataset
```bash
python backend/download_dataset.py
```
Download from one of these (both free):
- **UNB Official**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Kaggle (easier)**: https://www.kaggle.com/datasets/cicdataset/cicids2017

Place all `.csv` files inside the `dataset/` folder.

### Step 3 — Train Models
```bash
# Full training (~15-20 min):
python backend/train.py

# Fast test (50k rows, ~3 min):
python backend/train.py --fast

# Skip autoencoder (faster):
python backend/train.py --no-ae
```

### Step 4 — Start Server

**Windows** (Run as Administrator for live capture):
```
start_windows.bat
```

**Linux/macOS** (sudo for live capture):
```bash
chmod +x start_linux.sh
sudo ./start_linux.sh
```

### Step 5 — Open Dashboard
```
http://localhost:5000
```
Click **▶ Start Capture** → Attacks will appear in real-time!

---

## 🔧 Optional Setup (All Free)

### 📡 Telegram Alerts (5 minutes)
1. Open Telegram → search **@BotFather** → send `/newbot`
2. Follow steps → copy your **Bot Token**
3. Send any message to your bot
4. Open: `https://api.telegram.org/bot<TOKEN>/getUpdates`
5. Copy the `chat_id` from the response
6. Edit `backend/config.py`:
```python
TELEGRAM_ENABLED   = True
TELEGRAM_BOT_TOKEN = "1234567890:ABCdef..."
TELEGRAM_CHAT_ID   = "123456789"
```
Test from dashboard: **Settings → Test Telegram**

### 📧 Email Alerts (Gmail)
1. Google Account → Security → 2-Step Verification → **App Passwords**
2. Generate password for "Mail" → copy 16-character code
3. Edit `backend/config.py`:
```python
EMAIL_ENABLED   = True
EMAIL_SENDER    = "your@gmail.com"
EMAIL_PASSWORD  = "abcd efgh ijkl mnop"   # 16-char App Password
EMAIL_RECIPIENT = "alerts@example.com"
```

### 🔒 AbuseIPDB Threat Intel (optional)
1. Register free at https://www.abuseipdb.com
2. Account → API → Create Key
3. Edit `backend/config.py`:
```python
ABUSEIPDB_API_KEY = "your-key-here"
```
Free tier: **1000 IP checks/day**

### 🌱 Online Learning
```bash
pip install river
```
Then in `config.py`:
```python
ONLINE_LEARNING_ENABLED = True
```
Model updates itself in real-time from live traffic!

### 🐳 Docker Deployment
```bash
# Build and run
docker-compose up -d

# First-time training inside container
docker-compose exec cyberguard python3 backend/train.py --fast

# View logs
docker-compose logs -f
```

---

## 🏗️ Architecture

```
Network Interface
      │
      ▼
 PacketSniffer (Scapy)
  ├── IPv4 + IPv6
  ├── TCP / UDP / ICMP
  └── DNS layer
      │
      ├──────────────────→ DNSDetector
      │                   (tunneling, DGA, flood)
      │
      ▼
 FlowTracker
 (78 CICIDS2017 features)
      │
      ▼
 EnsembleDetector
 ┌───────────────────────────────────┐
 │ XGBoost (70%) + IsolationForest   │
 │ (30%) + Autoencoder Zero-Day      │
 └───────────────────────────────────┘
      │
      ▼
 AttackClassifier (Rule + ML hybrid)
      │
      ├──→ BehavioralProfiler   (per-IP threat score)
      ├──→ GeoMapper            (ip-api.com, free)
      ├──→ ThreatIntelChecker   (AbuseIPDB, optional)
      ├──→ AlertManager         (Telegram + Email)
      ├──→ AutoBlocker          (netsh/iptables)
      ├──→ PcapExporter         (Scapy .pcap)
      ├──→ OnlineLearner        (River, incremental)
      └──→ WebSocket Dashboard  (real-time)

HoneypotManager (7 fake ports)
      └──→ WebSocket Dashboard  (instant alerts)
```

---

## 📁 File Structure

```
cyberguard-v3/
├── backend/
│   ├── app.py                    # Main Flask server (v3)
│   ├── config.py                 # All config + feature names
│   ├── train.py                  # Training script
│   ├── sniffer.py                # Packet capture (IPv4+IPv6)
│   ├── flow_tracker.py           # 78-feature extractor
│   ├── detector.py               # XGBoost + IsolationForest
│   ├── classifier.py             # Rule + ML hybrid
│   ├── blocker.py                # Firewall auto-blocker
│   ├── logger_module.py          # Rotating JSON logs
│   ├── dataset_loader.py         # CICIDS2017 loader
│   ├── download_dataset.py       # Dataset guide
│   │
│   ├── geo_mapper.py             # 🆕 GeoIP (ip-api.com, free)
│   ├── alerting.py               # 🆕 Telegram + Email
│   ├── honeypot.py               # 🆕 Fake service ports
│   ├── behavioral_profiler.py    # 🆕 Per-IP threat scoring
│   ├── autoencoder_detector.py   # 🆕 Zero-Day detection
│   ├── online_learner.py         # 🆕 Incremental learning
│   ├── threat_intel.py           # 🆕 AbuseIPDB integration
│   ├── dns_detector.py           # 🆕 DNS attack detection
│   └── pcap_exporter.py          # 🆕 PCAP export
│
├── frontend/
│   └── index.html                # 🆕 Enhanced dashboard
│
├── dataset/                      # ← Place CICIDS2017 CSVs here
├── logs/                         # Auto-created rotating logs
├── pcap_exports/                 # Auto-created PCAP files
│
├── requirements.txt
├── Dockerfile                    # 🆕 Docker support
├── docker-compose.yml            # 🆕 Docker Compose
├── start_windows.bat
└── start_linux.sh
```

---

## ⚙️ Configuration Quick Reference

```python
# backend/config.py

# Firewall blocking (needs root/admin)
AUTO_BLOCK_ENABLED = False    # Set True to enable
BLOCK_THRESHOLD    = 3        # Attacks before auto-block
BLOCK_DURATION     = 3600     # Seconds (1 hour)

# Honeypot ports (fake services)
HONEYPOT_PORTS = [21, 22, 23, 3389, 8080, 1433, 3306]

# Telegram (free)
TELEGRAM_ENABLED   = False
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID   = ""

# Email (free)
EMAIL_ENABLED   = False
EMAIL_SENDER    = ""
EMAIL_PASSWORD  = ""
EMAIL_RECIPIENT = ""

# AbuseIPDB (free, optional)
ABUSEIPDB_API_KEY = ""

# Network interface (None = auto-detect)
INTERFACE = None   # e.g. "eth0" or "Wi-Fi"
```

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---|---|
| `No CSV files found` | Download CICIDS2017 → put in `dataset/` |
| `Permission denied` | Run as root/Administrator |
| `Model not ready` | Run `python backend/train.py` |
| `Scapy not found` | `pip install scapy` + Npcap on Windows |
| `Training too slow` | Use `--fast` flag |
| `Honeypot port in use` | Remove the port from `HONEYPOT_PORTS` in config.py |
| `Telegram not working` | Check token + chat_id; ensure bot is started |
| `GeoIP shows Unknown` | Private IPs are expected to show Unknown — normal |

---

## 🔑 Privilege Requirements

| Feature | Windows | Linux/macOS |
|---|---|---|
| Dashboard (no capture) | Normal user | Normal user |
| Live packet capture | Run as Administrator | sudo |
| IP blocking (iptables) | Run as Administrator | sudo |
| Honeypot (ports <1024) | Run as Administrator | sudo |

---

## 📊 Expected Model Accuracy (CICIDS2017)

| Model | Accuracy | F1 Score |
|---|---|---|
| XGBoost (this system) | ~98–99% | ~97–98% |
| RandomForest (fallback) | ~97–98% | ~96–97% |
| Autoencoder (zero-day) | ~85–90% detection | — |

---

*CyberGuard IDS v4 — All features free. No cloud required. Real CICIDS2017 data.*
