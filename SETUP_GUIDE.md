# 🛡️ CyberGuard IDS v4 — Complete Setup Guide
## Step-by-Step Installation + All API Keys Explained

---

## 💰 KHARCHA KITNA HOGA? (Cost Breakdown)

| Feature | Tool | Cost |
|---|---|---|
| ML Detection (XGBoost + Autoencoder) | scikit-learn, xgboost | **FREE** |
| Live Packet Capture | Scapy | **FREE** |
| GeoIP Map | ip-api.com | **FREE** (45 req/min, no key needed) |
| Honeypot | Python sockets | **FREE** |
| Behavioral Profiling | Pure Python | **FREE** |
| DNS Attack Detection | Scapy | **FREE** |
| PCAP Export | Scapy | **FREE** |
| Telegram Alerts | Telegram Bot API | **FREE** (unlimited) |
| Email Alerts | Gmail SMTP | **FREE** |
| Threat Intelligence | AbuseIPDB | **FREE** (1000 checks/day) |
| Online Learning | River library | **FREE** |
| Docker | Docker | **FREE** |

**TOTAL COST = ₹0 / $0 — Sab kuch FREE hai! 🎉**

---

## ⚡ QUICK START (Sirf 5 steps)

```bash
# Step 1: Dependencies install karo
pip install -r requirements.txt

# Step 2: .env file banao
cp .env.example .env

# Step 3 (OPTIONAL): Telegram/Email setup karo
python backend/setup_wizard.py

# Step 4: Models train karo (fast mode = 3 min)
python backend/train.py --fast    # 96%+ accuracy, ~5 min
python backend/train.py           # 98%+ accuracy, ~20 min

# Step 5: Server start karo
python backend/app.py         # Windows: start_windows.bat
# OR Linux with live capture:
sudo ./start_linux.sh
```

**Dashboard kholo:** http://localhost:5000

---

## 📋 DETAILED SETUP

### STEP 1 — Python Install

**Windows:**
1. https://python.org/downloads se Python 3.10+ download karo
2. Install karte time **"Add Python to PATH"** ✅ check karna zaroor
3. Restart computer

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv -y
```

---

### STEP 2 — Project Setup

```bash
# Project folder me jao
cd cyberguard-v4

# Dependencies install karo
pip install -r requirements.txt

# .env file banao
cp .env.example .env
```

---

### STEP 3 — Dataset + Model Training

**Option A — Fast Test (3 minutes, recommended for testing):**
```bash
python backend/train.py --fast    # 96%+ accuracy, ~5 min
python backend/train.py           # 98%+ accuracy, ~20 min
```
Ye pre-existing models use karta hai jo already `backend/models/` me hain.

**Option B — Full Training (15-20 minutes, best accuracy):**

1. CICIDS2017 dataset download karo:
   - **Kaggle (easy):** https://www.kaggle.com/datasets/cicdataset/cicids2017
   - Account banao (free) → Download → Extract
   - Ya: `python backend/download_dataset.py`

2. CSV files rakho `dataset/` folder me:
   ```
   cyberguard-v4/
   └── dataset/
       ├── Monday-WorkingHours.pcap_ISCX.csv
       ├── Tuesday-WorkingHours.pcap_ISCX.csv
       └── ... (baaki files)
   ```

3. Train karo:
   ```bash
   python backend/train.py
   ```

**Option C — Demo Mode (koi dataset nahi chahiye!):**
```bash
# Terminal 1: Server start karo
python backend/app.py

# Terminal 2: Fake traffic bhejo
python backend/demo_mode.py
```

---

### STEP 4 — Server Start Karo

**Windows (Normal mode — no live capture):**
```
start_windows.bat
```
Ya double-click karo `start_windows.bat`

**Windows (Live capture — Administrator chahiye):**
Right-click `start_windows.bat` → "Run as Administrator"

**Linux (Normal mode):**
```bash
python backend/app.py
```

**Linux (Live capture — root chahiye):**
```bash
sudo ./start_linux.sh
# OR
sudo python3 backend/app.py
```

**Dashboard:** http://localhost:5000

---

## 📡 TELEGRAM BOT SETUP (FREE — 10 minutes)

### Part A: Bot Token Kaise Milega

1. **Telegram app kholo** (mobile ya desktop)
2. Search karo: **@BotFather**
3. Click karo → **START** button dabao
4. Send karo: `/newbot`
5. BotFather poochega: **"What name do you want for your bot?"**
   - Koi bhi naam do jaise: `CyberGuard Alert`
6. Phir poochega: **"What username?"**
   - Username hamesha `bot` se khatam hona chahiye jaise: `cyberguard_mybot`
7. **Bot Token milega** — kuch aisa dikhega:
   ```
   7123456789:AAF-xyzABCdef12345...
   ```
   Ye token copy karo — ye hai tera **TELEGRAM_BOT_TOKEN**

### Part B: Chat ID Kaise Milega

1. Apne naye bot ko Telegram me search karo (jo username tune likha tha)
2. Bot ko open karo → **START** dabao ya `/start` bhejo
3. Ab browser me ye URL kholo (apna token daalo):
   ```
   https://api.telegram.org/bot7123456789:AAF-xyz.../getUpdates
   ```
   Replace karo `7123456789:AAF-xyz...` apne actual token se

4. Browser me JSON dikhega, kuch aisa:
   ```json
   {
     "result": [{
       "message": {
         "chat": {
           "id": 987654321,    ← YE HAI TERA CHAT ID!
           "type": "private"
         }
       }
     }]
   }
   ```
5. `"id":` ke baad jo number hai — wo hai tera **TELEGRAM_CHAT_ID**

> ⚠️ **Problem:** `"result":[]` dikh raha hai?
> → Bot ko `/start` bhejo pehle, phir URL dobara try karo

### Part C: .env File Me Daalo

`.env` file kholo aur fill karo:
```env
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=7123456789:AAF-xyzABCdef12345...
TELEGRAM_CHAT_ID=987654321
```

### Part D: Test Karo

1. Dashboard kholo: http://localhost:5000
2. **Settings tab** pe jao
3. **"Test Telegram"** button dabao
4. Telegram pe message aana chahiye: "🧪 CyberGuard test message"

Ya terminal se:
```bash
python backend/setup_wizard.py
```

---

## 📧 GMAIL ALERTS SETUP (FREE)

### Gmail App Password Kaise Banayein

> ⚠️ Normal Gmail password use mat karo — App Password chahiye

1. Google Account kholo: https://myaccount.google.com
2. Left side me **"Security"** click karo
3. **"2-Step Verification"** enable karo (agar nahi hai to)
4. Search karo **"App passwords"** ya yahan jao:
   https://myaccount.google.com/apppasswords
5. **"Select app"** → "Mail" chunao
6. **"Select device"** → "Other (Custom name)" → "CyberGuard" type karo
7. **"Generate"** dabao
8. **16-character password** milega jaise: `abcd efgh ijkl mnop`
9. Is password ko copy karo (spaces ke saath ya bina, dono chalega)

### .env File Me Daalo

```env
EMAIL_ENABLED=true
ALERT_EMAIL_FROM=tumhara@gmail.com
ALERT_EMAIL_PASS=abcdefghijklmnop
ALERT_EMAIL_TO=alerts@gmail.com
```

---

## 🔍 ABUSEIPDB SETUP (FREE — 1000 checks/day)

### API Key Kaise Milegi

1. https://www.abuseipdb.com/register pe register karo (free)
2. Email verify karo
3. Login → https://www.abuseipdb.com/account/api pe jao
4. **"Create Key"** dabao → Key copy karo

### .env File Me Daalo

```env
ABUSEIPDB_KEY=abcdef1234567890...
```

---

## 🐳 DOCKER SETUP (FREE)

### Prerequisites
- Docker Desktop: https://docker.com/products/docker-desktop (free)

### Run with Docker

```bash
# Single command — sab kuch automatically setup ho jayega
docker-compose up --build

# Background me chalao
docker-compose up -d

# Logs dekho
docker-compose logs -f

# Stop karo
docker-compose down
```

Dashboard: http://localhost:5000

---

## 🍯 HONEYPOT — Kaise Kaam Karta Hai

Honeypot automatically chalu hota hai. Ye fake ports kholta hai:

| Port | Pretends To Be |
|------|----------------|
| 21   | FTP Server     |
| 22   | SSH Server     |
| 23   | Telnet         |
| 3389 | Windows RDP    |
| 8080 | HTTP Server    |
| 1433 | MSSQL Database |
| 3306 | MySQL Database |

Jo bhi in ports ko scan kare ya connect kare, immediately alert milega!

> ⚠️ Port 22 (SSH) pehle se use ho sakta hai Linux pe
> Fix: `sudo systemctl stop ssh` ya config.py me `HONEYPOT_PORTS` se 22 hatao

---

## 🔒 LIVE CAPTURE — Permissions Fix

### Linux — "Permission denied" error

```bash
# Method 1: Root se chalao
sudo python3 backend/app.py

# Method 2: Python ko special permission do (better)
sudo setcap cap_net_raw+ep $(which python3)
python3 backend/app.py    # ab bina sudo ke chalega

# Method 3: User ko group me add karo
sudo usermod -aG wireshark $USER
# Logout aur login karo
```

### Windows — "WinError" ya "Npcap" error

1. Npcap download karo: https://npcap.com/#download
2. Install karo (default settings chalenge)
3. Restart karo
4. `start_windows.bat` **Right-click → Run as Administrator**

---

## ⚡ ONLINE LEARNING SETUP (FREE — Optional)

```bash
# River library install karo
pip install river

# .env me enable karo
# ONLINE_LEARNING_ENABLED=true
```
Tab restart karo server — model automatically real-time me update hoga!

---

## ❓ COMMON PROBLEMS

### "ModuleNotFoundError: No module named 'flask'"
```bash
pip install -r requirements.txt
```

### "Models not found — run train.py"
```bash
python backend/train.py --fast    # 96%+ accuracy, ~5 min
python backend/train.py           # 98%+ accuracy, ~20 min
```

### Dashboard opens but no data
- Live capture bina root ke nahi chalega
- Demo mode try karo:
  ```bash
  python backend/demo_mode.py
  ```

### Port 5000 already in use
- `config.py` me `PORT = 5001` kar do
- Ya `.env` me `PORT=5001`

### Honeypot port error (port already in use)
`.env` me ya `config.py` me se woh port hata do:
```python
HONEYPOT_PORTS = [21, 23, 3389, 8080, 1433, 3306]  # 22 hataya
```

### Telegram "Unauthorized" error
- Bot token galat hai — @BotFather se dobara check karo
- Token me koi extra space nahi hona chahiye

### Gmail "Authentication failed"
- Normal password use mat karo — App Password chahiye
- 2-Step Verification pehle enable karo Gmail me

---

## 📁 PROJECT STRUCTURE

```
cyberguard-v4/
├── .env                    ← Tumhara config (git ignore hai — safe)
├── .env.example            ← Template
├── requirements.txt        ← Python dependencies
├── start_linux.sh          ← Linux startup script
├── start_windows.bat       ← Windows startup script
├── docker-compose.yml      ← Docker setup
├── SETUP_GUIDE.md          ← Ye file (step-by-step guide)
│
├── backend/
│   ├── app.py              ← Main Flask server
│   ├── config.py           ← All settings
│   ├── train.py            ← ML model training
│   ├── demo_mode.py        ← Test without live capture ← NEW
│   ├── setup_wizard.py     ← Interactive config setup ← NEW
│   ├── detector.py         ← XGBoost + IsolationForest ensemble
│   ├── classifier.py       ← Attack rule-based classifier
│   ├── sniffer.py          ← Live packet capture
│   ├── flow_tracker.py     ← Network flow generation
│   ├── geo_mapper.py       ← GeoIP lookup
│   ├── alerting.py         ← Telegram + Email alerts
│   ├── honeypot.py         ← Fake service ports
│   ├── behavioral_profiler.py ← Per-IP threat scoring
│   ├── autoencoder_detector.py ← Zero-day detection
│   ├── dns_detector.py     ← DNS attack detection
│   ├── threat_intel.py     ← AbuseIPDB integration
│   ├── online_learner.py   ← Incremental ML (River)
│   ├── pcap_exporter.py    ← PCAP file export
│   ├── blocker.py          ← Auto IP blocking
│   ├── logger_module.py    ← Alert logging
│   └── models/             ← Trained ML models (after train.py)
│
├── frontend/
│   └── index.html          ← Dashboard (single file, no build needed)
│
├── dataset/                ← Put CICIDS2017 CSV files here
├── logs/                   ← Alert logs (auto-created)
└── pcap_exports/           ← PCAP files (auto-created)
```

---

## 🔑 API KEYS SUMMARY

| Key | Where to get | Cost | Required? |
|-----|-------------|------|-----------|
| `TELEGRAM_BOT_TOKEN` | @BotFather on Telegram | FREE | Optional |
| `TELEGRAM_CHAT_ID` | Browser URL trick | FREE | Optional |
| `ALERT_EMAIL_FROM` | Your Gmail address | FREE | Optional |
| `ALERT_EMAIL_PASS` | Google Account → App Passwords | FREE | Optional |
| `ABUSEIPDB_KEY` | abuseipdb.com/register | FREE (1000/day) | Optional |

**Koi bhi mandatory nahi hai.** Sab optional features hain.

---

## 📞 SUPPORT

Koi problem aaye to:
1. Pehle ye file padho — 90% problems yahan solve hain
2. Demo mode try karo: `python backend/demo_mode.py`
3. Logs dekho: `logs/` folder me

**Project by:** CyberGuard IDS v4
**For:** MCA Research Project — LPU
