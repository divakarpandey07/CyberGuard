import os
import re
import ast

class CodebaseParser:
    def __init__(self, root_dir):
        self.root_dir = root_dir
        
    def scan(self):
        kb = {}
        backend_dir = os.path.join(self.root_dir, "backend")
        if not os.path.exists(backend_dir):
            return kb
            
        for file in os.listdir(backend_dir):
            if file.endswith(".py"):
                path = os.path.join(backend_dir, file)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        code = f.read()
                    kb[file] = self._parse_file(file, code)
                except Exception:
                    pass
        return kb

    def _parse_file(self, filename, content):
        info = {
            "summary": "",
            "classes": {},
            "functions": [],
            "imports": []
        }
        
        # Extract file summary from docstring
        docstring_match = re.match(r'^"""(.*?)"""', content, re.DOTALL)
        if docstring_match:
            info["summary"] = docstring_match.group(1).strip().split("\n")[0]
            
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        info["imports"].append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    info["imports"].append(node.module or "")
                elif isinstance(node, ast.ClassDef):
                    class_info = {
                        "methods": [],
                        "docstring": ast.get_docstring(node) or ""
                    }
                    for subnode in node.body:
                        if isinstance(subnode, ast.FunctionDef):
                            class_info["methods"].append({
                                "name": subnode.name,
                                "args": [arg.arg for arg in subnode.args.args],
                                "docstring": ast.get_docstring(subnode) or ""
                            })
                    info["classes"][node.name] = class_info
                elif isinstance(node, ast.FunctionDef) and not isinstance(node, ast.ClassDef):
                    info["functions"].append({
                        "name": node.name,
                        "args": [arg.arg for arg in node.args.args],
                        "docstring": ast.get_docstring(node) or ""
                    })
        except Exception:
            pass
            
        return info

def answer_query(query, root_dir):
    import json, time
    query_lower = query.lower().strip()
    
    if query_lower.startswith("[audit_data]"):
        try:
            # Strip prefix
            json_str = query[len("[audit_data]"):].strip()
            data = json.loads(json_str)
        except Exception:
            data = {}
            
        # Extract fields
        cpu = data.get("cpu", 0)
        ram = data.get("ram", 0)
        total_flows = data.get("total_flows", 0)
        attacks_detected = data.get("attacks_detected", 0)
        ips_blocked = data.get("ips_blocked", 0)
        honeypot_active = data.get("honeypot_active", False)
        honeypot_hits = data.get("honeypot_hits", 0)
        dns_queries = data.get("dns_queries", 0)
        dns_attacks = data.get("dns_attacks", 0)
        tg_enabled = data.get("tg_enabled", False)
        email_enabled = data.get("email_enabled", False)
        intel_active = data.get("intel_active", False)
        ml_ready = data.get("ml_ready", False)
        ml_accuracy = data.get("ml_accuracy", 0.0)
        ae_ready = data.get("ae_ready", False)
        online_learning = data.get("online_learning", False)
        auto_block = data.get("auto_block", False)
        active_interface = data.get("active_interface", "None")

        # Calculate security score
        score = 0
        if ml_ready: score += 20
        if ae_ready: score += 20
        if honeypot_active: score += 20
        if auto_block: score += 20
        if tg_enabled or email_enabled: score += 20
        
        rating = "F (CRITICAL - SYSTEM VULNERABLE)"
        if score >= 100: rating = "A+ (EXCELLENT PROTECTION)"
        elif score >= 80: rating = "A (STRONG DEFENSE)"
        elif score >= 60: rating = "B (MODERATE DEFENSE)"
        elif score >= 40: rating = "C (WEAK PROTECTION)"
        elif score >= 20: rating = "D (VULNERABLE)"

        # Generate recommendations
        recs = []
        if not ml_ready:
            recs.append("- **Train Supervised Models**: Run `python backend/train.py` to activate XGBoost and Isolation Forest detectors.")
        if not ae_ready:
            recs.append("- **Configure Autoencoder**: Run a complete model training process to activate the Zero-day detection engine.")
        if not auto_block:
            recs.append("- **Enable Intrusion Prevention (IPS)**: Turn on 'Auto IP Blocking' in Settings to automatically ban threats.")
        if not tg_enabled:
            recs.append("- **Setup Telegram Notifications**: Configure Telegram Alerts to get instant mobile alerts when threats occur.")
        if not email_enabled:
            recs.append("- **Setup Email Alerts**: Bind SMTP settings in the configuration manager for permanent logs.")
        if not intel_active:
            recs.append("- **Register AbuseIPDB**: Add your API key to compare attacking IPs against international threat indexes.")
        if len(recs) == 0:
            recs.append("- **System Configured Correctly**: All primary defense shields are active! Keep monitoring system logs regularly.")

        # Build response without any '#'
        report = (
            "**🛡️ CYBERGUARD IDS V4 — REAL-TIME SECURITY AUDIT REPORT**\n\n"
            f"**Audit Date:** {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"**Current Security Rating:** **{rating}** (Score: {score}/100)\n"
            f"**Active Interface:** `{active_interface}`\n\n"
            "**📊 SYSTEM TELEMETRY SUMMARY**\n"
            f"- CPU Usage: `{cpu}%` │ Memory (RAM) Usage: `{ram}%`\n"
            f"- Traffic Monitored: `{total_flows}` reassembled flows\n"
            f"- Attacks Blocked: `{ips_blocked}` active IP bans\n"
            f"- Honeypot Decoys: `{'ACTIVE' if honeypot_active else 'INACTIVE'}` (Hits intercepted: `{honeypot_hits}`)\n"
            f"- DNS Protection: `{dns_queries}` query inspects │ Attacks flagged: `{dns_attacks}`\n\n"
            "**🛡️ PROTECTION SHIELD MATRIX**\n"
            f"- Supervised Classifiers (XGBoost/Isolation Forest): `{'READY (' + str(round(ml_accuracy*100, 1)) + '% acc)' if ml_ready else 'NOT TRAINED'}`\n"
            f"- Unsupervised Zero-Day Autoencoder: `{'READY' if ae_ready else 'NOT TRAINED'}`\n"
            f"- Online Incremental Learning (River): `{'ENABLED' if online_learning else 'DISABLED'}`\n"
            f"- Auto-Blocking Intrusion Prevention System: `{'ENABLED' if auto_block else 'DISABLED'}`\n"
            f"- Telegram Notification Tunnel: `{'CONFIGURED' if tg_enabled else 'NOT CONFIGURED'}`\n"
            f"- SMTP Email Alerts Channel: `{'CONFIGURED' if email_enabled else 'NOT CONFIGURED'}`\n"
            f"- AbuseIPDB Threat Intel Registry: `{'ACTIVE' if intel_active else 'NOT CONFIGURED'}`\n\n"
            "**💡 SECURITY HARDENING RECOMMENDATIONS**\n"
            + "\n".join(recs) + "\n\n"
            "This report is generated dynamically by your local CyberGuard AI Security Copilot model based on current system memory states."
        )
        return report.replace('#', '')

    parser = CodebaseParser(root_dir)
    kb = parser.scan()
    
    query = query_lower
    
    file_explanations = {
        "app.py": (
            "**📂 backend/app.py - Main Server & Pipeline Controller**\n\n"
            "This is the heart of CyberGuard IDS. It initializes the Flask web server, configures Socket.IO for real-time web communication, and runs the background processing loop that polls completed network flows from the flow tracker.\n\n"
            "It coordinates all detection actions: checking flows against the ensemble classifier, checking for zero-day anomalies using the Autoencoder, logging security alerts, triggering the firewall blocker, and sending push notifications."
        ),
        "sniffer.py": (
            "**📂 backend/sniffer.py - Live Packet Sniffer**\n\n"
            "This module handles capturing raw network packets. It uses the **Scapy** library to attach to your system's network interface adapter. It runs in a background thread, sniffing packets and feeding them immediately to the Flow Tracker, the DNS Detector, and the PCAP Exporter."
        ),
        "flow_tracker.py": (
            "**📂 backend/flow_tracker.py - Bidirectional Flow Reassembler**\n\n"
            "This file groups individual, transient packets into cohesive bidirectional communication flows based on their 5-tuple (source IP, destination IP, source port, destination port, and protocol).\n\n"
            "For each flow, it computes statistical features required by the machine learning models, such as flow duration, byte and packet rates, and TCP flag counts."
        ),
        "detector.py": (
            "**📂 backend/detector.py - Machine Learning Detection Engine**\n\n"
            "This module handles loading and running the pre-trained supervised machine learning models. It manages the **XGBoost Classifier** and the **Isolation Forest** model, feeding them normalized flow features to predict whether traffic is Benign, DoS/DDoS, PortScan, or Infiltration."
        ),
        "classifier.py": (
            "**📂 backend/classifier.py - Heuristic Rule & Overrides Engine**\n\n"
            "This script is the decision-maker that combines ML predictions with deterministic rules. It parses features to override ML classifications if a rule matches (e.g. for simulated attacks or absolute thresholds) and adds recommendation texts and severity levels (LOW, MEDIUM, HIGH, CRITICAL) to the alerts."
        ),
        "blocker.py": (
            "**📂 backend/blocker.py - Automated Firewall Blocker**\n\n"
            "This module executes host firewall block commands. When an IP address accumulates too many strikes (malicious detections), the blocker runs system commands (`netsh` on Windows, `iptables` on Linux) to drop all packets from that IP. Block rules are kept in memory and automatically unblocked after 1 hour."
        ),
        "honeypot.py": (
            "**📂 backend/honeypot.py - Active Decoy System**\n\n"
            "This script starts simple socket listeners on common decoy ports (like 21, 22, 23, 3306, 8080). If scanner bots or unauthorized users try to connect to these ports, the honeypot intercepts the request, flags the IP, and triggers an immediate critical alert and auto-block."
        ),
        "dns_detector.py": (
            "**📂 backend/dns_detector.py - DNS Traffic Inspector**\n\n"
            "This module analyzes DNS query names and query length to identify suspicious activity. It flags excessively long domain names (often associated with DNS Tunneling or data exfiltration), suspicious top-level domains, and high ratios of uppercase letters."
        ),
        "alerting.py": (
            "**📂 backend/alerting.py - Telegram & SMTP Email Alerts Dispatcher**\n\n"
            "This file handles outbound communications. When a security threat is identified, it generates alert summaries and dispatches them via background threads to a Telegram Channel (using the Telegram Bot API) and to an administrator's email inbox using secure SMTP."
        ),
        "autoencoder_detector.py": (
            "**📂 backend/autoencoder_detector.py - PyTorch Zero-Day Anomaly Detector**\n\n"
            "This file contains our deep learning Autoencoder model. It is trained only on benign network traffic. If an incoming flow causes a high reconstruction error (meaning it differs significantly from the normal baseline), the system flags it as a Zero-Day threat."
        ),
        "geo_mapper.py": (
            "**📂 backend/geo_mapper.py - Offline IP Geo-IP Resolver**\n\n"
            "This module resolves public IP addresses to latitude/longitude coordinates and country details using offline MaxMind GeoLite databases. It is used to plot attacker locations dynamically on the dashboard map."
        ),
        "behavioral_profiler.py": (
            "**📂 backend/behavioral_profiler.py - Host Risk Profiler**\n\n"
            "This file records activity profiles for individual IP addresses. It calculates overall threat scores and updates host risk levels (LOW, MEDIUM, HIGH, CRITICAL) over time based on the frequency and severity of their malicious activities."
        ),
        "online_learner.py": (
            "**📂 backend/online_learner.py - Incremental Online Machine Learning**\n\n"
            "This module implements online incremental learning using the `river` Python library. It updates its parameters on-the-fly with each incoming packet flow, allowing the system to adapt dynamically to new network behaviors without complete offline retraining."
        ),
        "threat_intel.py": (
            "**📂 backend/threat_intel.py - Threat Intelligence Lookup**\n\n"
            "This script queries external security intelligence databases (such as AbuseIPDB) to check the reputation score of incoming IP addresses, adding global threat data to our local classifications."
        ),
        "pcap_exporter.py": (
            "**📂 backend/pcap_exporter.py - Raw Packet Buffer & PCAP Exporter**\n\n"
            "This module retains a rolling buffer of raw packet bytes in memory. Clicking the PCAP export button in the dashboard allows you to download these packets as a standard `.pcap` file for detailed analysis in Wireshark."
        ),
        "config.py": (
            "**📂 backend/config.py - Environment & System Configuration Settings**\n\n"
            "This script loads settings from your `.env` configuration file. It manages threshold parameters, honeypot ports, whitelist IPs, Telegram/Email access tokens, and feature indices for the ML models."
        ),
        "train.py": (
            "**📂 backend/train.py - ML Model Offline Training Script**\n\n"
            "This script preprocesses the raw flow dataset (scaling metrics, splitting normal/attack features) and trains our three models (XGBoost, Isolation Forest, PyTorch Autoencoder), saving the outputs as binary files in backend/models/."
        ),
        "setup_wizard.py": (
            "**📂 backend/setup_wizard.py - Configuration Helper CLI**\n\n"
            "This is an interactive command-line wizard that guides the user through setting up network adapters, Telegram bot tokens, email addresses, and server configurations, automatically building the `.env` file."
        )
    }

    class_explanations = {
        "EnsembleDetector": (
            "**🤖 EnsembleDetector Class (backend/detector.py)**\n\n"
            "This class is the core ML interface. It loads the XGBoost model (`xgb_model.pkl`) and the Isolation Forest model (`iso_forest.pkl`). It performs metric predictions and returns confidence scores and attack classifications."
        ),
        "PacketSniffer": (
            "**📡 PacketSniffer Class (backend/sniffer.py)**\n\n"
            "This class starts a background thread utilizing Scapy's `sniff` API to capture packets live. It includes error checks, adapter configuration, and relays raw bytes to the flow tracker."
        ),
        "FlowTracker": (
            "**📊 FlowTracker Class (backend/flow_tracker.py)**\n\n"
            "This class tracks active network sockets. It aggregates raw packets into a dictionary of active connections, calculates duration and flag counts, and cleans up expired connections."
        ),
        "AutoBlocker": (
            "**🔒 AutoBlocker Class (backend/blocker.py)**\n\n"
            "This class manages active defensive actions. It tracks strike histories per IP, verifies whitelists, and runs OS shell commands (`netsh` or `iptables`) to block/unblock malicious hosts."
        ),
        "HoneypotManager": (
            "**🍯 HoneypotManager Class (backend/honeypot.py)**\n\n"
            "This class manages active trap ports. It starts standard TCP sockets on decoy ports and executes callback functions to notify the main app when an unauthorized probe is received."
        ),
        "DNSDetector": (
            "**🌐 DNSDetector Class (backend/dns_detector.py)**\n\n"
            "This class parses DNS request packets. It extracts query domains, flags anomalies, and logs suspicious queries to prevent DNS tunneling attacks."
        ),
        "AlertManager": (
            "**🚨 AlertManager Class (backend/alerting.py)**\n\n"
            "This class dispatches alerts. It handles SMTP email headers and triggers Telegram API HTTP POST requests while applying cooldown safety filters."
        ),
        "AutoencoderDetector": (
            "**🧠 AutoencoderDetector Class (backend/autoencoder_detector.py)**\n\n"
            "This class manages our deep learning anomaly model. It includes PyTorch model parameters, reconstruction evaluation steps, and baseline training routines."
        ),
        "GeoMapper": (
            "**🌍 GeoMapper Class (backend/geo_mapper.py)**\n\n"
            "This class performs coordinate resolution. It loads offline database maps and resolves public IPs to geographic coordinates for frontend visualization."
        )
    }

    # 0. Check for greetings
    greetings = ["hi", "hello", "hey", "hii", "hola", "greetings", "good morning", "good afternoon", "good evening", "namaste", "pranam"]
    if any(query == g or query.startswith(g + " ") or query.endswith(" " + g) or query.replace("?", "").strip() == g for g in greetings):
        return (
            "**👋 Hello there! How can I help you today?**\n\n"
            "I am your local offline CyberGuard AI Security Copilot. I can explain the inner workings of this Intrusion Detection System, its machine learning models, configuration parameters, or python source code files.\n\n"
            "Here are some examples of what you can ask me:\n"
            "- **what is ids?** - Explains the overall system architecture\n"
            "- **what is sniffer.py?** - Describes the packet sniffing logic\n"
            "- **how does the ensemble detector work?** - Explains our ML detection engine\n"
            "- **tell me about this project** - Gives a detailed overview of all modules\n\n"
            "Feel free to ask me anything about your project's files or security concepts!"
        )

    # 1. Custom High-Relevance Local Security Concepts FAQs (NO '#' characters)
    # 1. Custom High-Relevance Local Security Concepts FAQs (NO '#' characters)
    faq_responses = {
        ("libraries", "library", "packages", "dependencies", "requirements", "installed", "pip"): (
            "**📦 Python Libraries Used in CyberGuard IDS v4**\n\n"
            "Here is the complete list of all third-party libraries and modules used in this project, categorized by their function:\n\n"
            "1. **Web & Communication (Flask Stack)**:\n"
            "   - `flask` (v2.3.0+): Powers our backend REST API server.\n"
            "   - `flask-cors`: Enables Cross-Origin Resource Sharing so our frontend can securely communicate with the API.\n"
            "   - `flask-socketio`, `python-socketio`, `python-engineio`: Implements bidirectional WebSockets for real-time traffic updates, live map plots, stats, and notification telemetry.\n\n"
            "2. **Network Packet Sniffing (Scapy)**:\n"
            "   - `scapy` (v2.5.0+): The core engine for raw packet capture. It binds to the host network interface in a background thread (`sniffer.py`), captures live packets, extracts protocol headers, and routes them to our analyzer pipeline.\n\n"
            "3. **Machine Learning & Core Math**:\n"
            "   - `xgboost` (v2.0.0+): Implements the Supervised Extreme Gradient Boosting Classifier used for ultra-fast multi-class classification of network attacks.\n"
            "   - `scikit-learn` (v1.3.0+): Powers unsupervised anomaly detection:\n"
            "     - `IsolationForest`: Identifies statistical outliers.\n"
            "     - `MLPRegressor`: Trains and runs our deep learning neural Autoencoder model.\n"
            "   - `numpy` & `pandas`: Handle raw feature matrix manipulation, normalization, and scaling calculations.\n"
            "   - `joblib`: Handles model serialization to save and load pre-trained `.pkl` files dynamically.\n\n"
            "4. **Telemetry & Threat Intelligence**:\n"
            "   - `psutil`: Collects host hardware health metrics (CPU %, RAM %, upload/download bandwidth throughput).\n"
            "   - `requests`: Dispatches background HTTP POST requests to the Telegram Bot API and queries AbuseIPDB for real-time external IP reputation checks.\n"
            "   - `gdown`: Downloads our training datasets from Google Drive during setup.\n\n"
            "5. **Online/Incremental Machine Learning (Optional)**:\n"
            "   - `river` (v0.21.0+): Supports incremental learning, allowing model updates sample-by-sample dynamically in real-time."
        ),
        ("algorithms", "algorithm", "xgboost", "isolation forest", "autoencoder", "shannon entropy", "math", "xgb"): (
            "**🧮 Security & Machine Learning Algorithms Used**\n\n"
            "CyberGuard combines multiple algorithmic models to detect network intrusions with zero latency:\n\n"
            "1. **XGBoost (Extreme Gradient Boosting)**:\n"
            "   - *Type*: Supervised gradient-boosted decision tree ensemble.\n"
            "   - *Purpose*: Classifies network flows into specific categories: Benign, DDoS/DoS, PortScan, or Infiltration.\n"
            "   - *How it works*: It sequentially builds decision trees, where each tree minimizes the residual errors of the previous one using gradient descent. It's incredibly fast and accurate.\n\n"
            "2. **Isolation Forest**:\n"
            "   - *Type*: Unsupervised anomaly detection algorithm.\n"
            "   - *Purpose*: Detects statistical out-of-distribution behaviors in flow features.\n"
            "   - *How it works*: Instead of profiling normal data, it isolates anomalies explicitly. It builds a forest of random partition trees; since anomalous flows have extreme feature values, they require far fewer splits (shorter path lengths) to be isolated.\n\n"
            "3. **Neural Autoencoder (MLP Neural Network)**:\n"
            "   - *Type*: Unsupervised deep learning neural network.\n"
            "   - *Purpose*: Identifies zero-day (previously undocumented) threats.\n"
            "   - *How it works*: Trained only on benign network flows. The encoder compresses 78 input metrics into a compressed latent representation, and the decoder attempts to reconstruct the original inputs. If the reconstruction error (Mean Squared Error) exceeds a strict threshold, it indicates that the traffic has abnormal structures and flags it as a Zero-Day.\n\n"
            "4. **Shannon Entropy (DNS Anomaly Detection)**:\n"
            "   - *Type*: Information theory mathematical algorithm.\n"
            "   - *Formula*: H(X) = -sum(P(x_i) * log2(P(x_i)))\n"
            "   - *Purpose*: Used in `dns_detector.py` to identify DNS Tunneling and Domain Generation Algorithms (DGA).\n"
            "   - *How it works*: Measures the randomness of characters in domain names. Natural language domains have low entropy, while randomized base64 strings or algorithmically generated domains show high randomness (entropy > 3.8), triggering alert rules.\n\n"
            "5. **Bidirectional Flow Reassembly (5-Tuple Algorithm)**:\n"
            "   - *Type*: Network state-tracking algorithm.\n"
            "   - *Purpose*: Groups individual packets into bidirectional streams.\n"
            "   - *How it works*: Hashes packets using a 5-tuple key: (Source IP, Destination IP, Source Port, Destination Port, Protocol). Tracks state variables (duration, packets/sec, bytes/sec, inter-arrival times, and TCP flag counts) to build a unified flow representation for ML inference."
        ),
        ("concepts", "concept", "machine learning", "ml", "concept", "concepts", "supervised", "unsupervised", "online learning", "incremental"): (
            "**🧠 Machine Learning (ML) Concepts & Paradigms in CyberGuard**\n\n"
            "Our Intrusion Detection and Prevention System implements three main Machine Learning paradigms:\n\n"
            "1. **Supervised Learning (Multi-Class Classification)**:\n"
            "   - *Concept*: Training a model on labeled training datasets (inputs paired with their corresponding correct labels).\n"
            "   - *Application*: The XGBoost classifier is trained on the CICIDS2017 dataset containing normal traffic and labeled attack classes (DDoS, PortScan, Infiltration). During runtime, it uses these pre-learned classification boundaries to predict the specific type of threat with high confidence.\n\n"
            "2. **Unsupervised Learning (Anomaly Detection)**:\n"
            "   - *Concept*: Detecting hidden patterns or outliers in unlabeled data without prior training on specific attack signatures.\n"
            "   - *Application*:\n"
            "     - **Isolation Forest**: Analyzes metric anomalies across all flow fields.\n"
            "     - **Autoencoder Neural Network**: Compresses and reconstructs benign traffic patterns. By monitoring reconstruction loss, it detects zero-day attacks that do not match any known signatures.\n\n"
            "3. **Online/Incremental Machine Learning**:\n"
            "   - *Concept*: Learning continuously from stream-based data. Traditional ML models are static and require offline retraining; online models update their internal parameters on-the-fly sample-by-sample.\n"
            "   - *Application*: Handled by the `river` library in `online_learner.py`. It monitors live network traffic and incrementally updates its classification baseline, allowing the system to adapt to normal network drift without service interruption.\n\n"
            "4. **Feature Engineering & Dimensionality Reduction**:\n"
            "   - *Concept*: Selecting, cleaning, and transforming raw network headers into structured numerical vectors.\n"
            "   - *Application*: The Flow Tracker processes raw Scapy packets and extracts 78 mathematical features (durations, flag rates, byte counts, IATs) which are scaled and normalized before being passed to our model detectors."
        ),
        ("ids", "ips", "intrusion", "what is ids"): (
            "**🛡️ Intrusion Detection & Prevention System (IDS/IPS)**\n\n"
            "An **IDS** monitors network traffic for suspicious activity and known threats. In this project, **CyberGuard IDS v4** sniffs live network packets using Scapy and parses them in real-time.\n\n"
            "Once a threat is classified by the XGBoost ML model or custom rules, the system acts as an **IPS (Intrusion Prevention System)** by automatically adding firewall block rules via `blocker.py` and sending a Telegram notification."
        ),
        ("scapy", "sniffing", "capture"): (
            "**📡 Scapy Packet Capture Library**\n\n"
            "**Scapy** is the core packet-sniffing engine used in `backend/sniffer.py`:\n\n"
            "- It listens to raw packets passing through your selected network adapter.\n"
            "- It decodes lower-level headers (TCP, UDP, ICMP, IPv6).\n"
            "- These parsed packets are sent to `backend/flow_tracker.py` to reassemble them into bidirectional network flows for ML processing.\n\n"
            "**Note:** Sniffing network sockets requires Administrator/Root privileges, which is why you must run CMD as Administrator."
        ),
        ("project", "cyberguard", "about", "overview"): (
            "**🛡️ CyberGuard IDS v4 - Project Overview**\n\n"
            "**CyberGuard IDS v4** is a modern, next-generation network security system. Here is a summary of its key modules:\n\n"
            "- **Supervised ML Classifier (`detector.py`)**: XGBoost Classifier trained on the CICIDS2017 dataset to identify threats (DDoS, PortScan, Infiltration).\n"
            "- **Zero-Day Detector (`autoencoder_detector.py`)**: Autoencoder neural network checking reconstruction error to flag undocumented anomalies.\n"
            "- **Live Threat Map**: Powered by Leaflet, it resolves IP geolocations (green for normal, red for attacks) dynamically.\n"
            "- **Honeypot Decoy Traps (`honeypot.py`)**: Sets up fake services on ports 21, 22, 23, 8080, etc. to trap scanning bots.\n"
            "- **Auto-Blocker (`blocker.py`)**: Blocks malicious IPs using Windows Firewall (`netsh`) or Linux `iptables`.\n"
            "- **Alerts (`alerting.py`)**: Dispatches alerts to Telegram bots and Emails."
        ),
        ("telegram", "alert", "bot", "notification", "email"): (
            "**🚨 Alerting System (Telegram & Email)**\n\n"
            "When an attack is detected, the `backend/alerting.py` module dispatches instant alerts:\n\n"
            "- **Telegram**: The bot sends details (Attack label, Source IP, Target Port, and Severity) directly to your Telegram chat. You configure this in your `.env` file with `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.\n"
            "- **Email**: Sends a detailed SMTP notification (like Gmail App Password) to your inbox.\n\n"
            "Both alerting channels run on background threads with a 30-second cooldown per alert category to avoid spamming."
        ),
        ("honeypot", "trap", "decoy"): (
            "**🍯 Active Honeypot Decoys**\n\n"
            "The honeypot system (`backend/honeypot.py`) sets up decoy socket listeners on common target ports (like 21 for FTP, 22 for SSH, 23 for Telnet, 1433 for MSSQL, 3306 for MySQL, 8080 for HTTP). \n\n"
            "If an attacker or scanning script scans your computer and attempts to connect to these decoy ports, the honeypot triggers an alarm, records the IP, and blocks them automatically. It is a highly effective way to catch reconnaissance scans early!"
        ),
        ("blocker", "block", "firewall"): (
            "**🔒 Automated Firewall Blocker**\n\n"
            "The auto-blocker (`backend/blocker.py`) acts as the defense shield:\n\n"
            "- It keeps track of strikes (malicious detections) per IP.\n"
            "- If an IP exceeds the block threshold (default: 3 strikes), it automatically triggers a firewall rule.\n"
            "- On **Windows**, it runs `netsh advfirewall` commands. On **Linux**, it uses `iptables`.\n"
            "- Blocked IPs are listed in the **Blocked IPs** tab on your dashboard, and they are automatically unblocked after 1 hour (configurable in `config.py` via `BLOCK_DURATION`)."
        ),
        ("flow", "packet", "sniffer", "sniff", "tracker"): (
            "**📡 Sniffing & Flow Reassembly**\n\n"
            "Network detection requires analyzing network flows, not just individual packets. Here is how CyberGuard reassembles them:\n\n"
            "1. **Sniffing (`sniffer.py`)**: Sniffs packets from the network adapter using Scapy.\n"
            "2. **Flow Tracking (`flow_tracker.py`)**: Reassembles packets into bidirectional flows using a 5-tuple key: (Source IP, Destination IP, Source Port, Destination Port, Protocol).\n"
            "3. **Feature Extraction**: Computes duration, byte rates, packet counts, inter-arrival times, and flag counts.\n"
            "4. **ML Inference**: Sends the completed flow features to the ML classifier for threat evaluation."
        ),
        ("dataset", "cicids"): (
            "**📊 Training Dataset (CICIDS2017)**\n\n"
            "The ML models are trained on the **CICIDS2017 dataset**, which is the gold standard for intrusion detection systems.\n\n"
            "It contains realistic network behavior (HTTP, HTTPS, FTP, SSH) and matches modern attack profiles including DoS/DDoS (Hulk, GoldenEye, Slowloris), Port Scans, and Infiltration. This ensures that the detection matches real-world attack behaviors!"
        ),
        ("run", "start", "cmd", "execute", "launch"): (
            "**🚀 Starting the CyberGuard Server**\n\n"
            "To start the server:\n\n"
            "1. Search for **cmd** in the Start Menu, right-click, and select **Run as Administrator**.\n"
            "2. Run the commands:\n"
            "   ```cmd\n"
            "   cd /d C:\\Users\\hp\\OneDrive\\Desktop\\CyberGuard\n"
            "   start_windows.bat\n"
            "   ```\n"
            "3. Open **http://localhost:5000** in your browser."
        ),
        ("ddos", "dos", "ddos attack"): (
            "**🔥 DDoS / DoS (Denial of Service) Attacks**\n\n"
            "A Denial of Service (DoS) or Distributed Denial of Service (DDoS) attack attempts to overwhelm a server with garbage traffic.\n\n"
            "CyberGuard monitors features like `syn_flag_count`, `flow_duration`, and `flow_packets_s`. When a source IP floods the server with TCP SYN packets, CyberGuard classifies it as DoS/DDoS, blocks the attacker IP, and alerts the administrator."
        ),
        ("portscan", "port scan"): (
            "**🔍 PortScan Reconnaissance Attacks**\n\n"
            "A PortScan attack occurs when an attacker sweeps your IP address looking for open ports (like 22 for SSH or 80 for HTTP) to find entry points.\n\n"
            "CyberGuard tracks TCP flags and destination port counts. If a single IP triggers connections across a series of ports, the rules in `backend/classifier.py` identify it as a PortScan attack and block the IP."
        ),
        ("infiltration", "hack", "penetration"): (
            "**⚡ Infiltration Attacks**\n\n"
            "Infiltration refers to exploits where an external attacker leverages vulnerabilities to gain internal system access.\n\n"
            "CyberGuard detects Infiltration by inspecting forward/backward byte ratios, flow duration anomalies, and packet sizes. Our pre-trained XGBoost model uses these pattern behaviors to identify and prevent unauthorized system breach attempts."
        ),
        ("dns", "domain", "dga", "dns_detector", "tunneling"): (
            "**🌐 DNS Attack Detection (dns_detector.py)**\n\n"
            "DNS (Domain Name System) resolves human-readable domain names to IP addresses. CyberGuard monitors DNS queries to detect threats:\n\n"
            "- **DNS Tunneling**: Attackers encode stolen data inside long, base64 subdomains (e.g. `secretdata123.malicious.com`). If a subdomain length exceeds 50 characters, CyberGuard flags it as a HIGH severity threat.\n"
            "- **DGA (Domain Generation Algorithms)**: Malware dynamically generates random-looking domains to bypass blocking. CyberGuard calculates **Shannon Entropy** (randomness). High entropy (>3.8) or consonant clusters trigger DGA alerts."
        ),
        ("autoencoder", "anomaly", "zero-day", "zeroday", "reconstruction", "neural network"): (
            "**🧠 Neural Autoencoder & Zero-Day Anomaly Detection**\n\n"
            "An **Autoencoder** is a deep learning model (using scikit-learn's `MLPRegressor` in `backend/autoencoder_detector.py`) used for unsupervised anomaly detection:\n\n"
            "- **Normal baseline**: It is trained purely on benign network traffic to compress and reconstruct normal metrics.\n"
            "- **Zero-Day**: Unknown attacks trigger a high reconstruction error (MSE) when the model fails to reconstruct the foreign pattern. If this error exceeds the baseline threshold, it overrides normal status and flags it as a **Zero-Day** anomaly."
        ),
        ("online", "learn", "incremental", "river", "online_learner"): (
            "**🔄 Incremental Online Learning (online_learner.py)**\n\n"
            "Unlike traditional machine learning models that require complete offline retraining, CyberGuard implements **online learning** via the **River** library:\n\n"
            "- It learns from incoming flows on-the-fly, one sample at a time.\n"
            "- It continuously updates its models to adapt to changes in your network's normal baseline without service interruption."
        ),
        ("geo", "map", "location", "geoip", "country", "latitude", "longitude", "geo_mapper"): (
            "**🌍 Dynamic GeoIP Mapping (geo_mapper.py)**\n\n"
            "CyberGuard maps connection origins in real-time:\n\n"
            "- **Offline Database**: Resolves IP addresses to coordinates, country names, city names, and country flags offline using MaxMind database files.\n"
            "- **Interactive Map**: Displayed via Leaflet.js on the dashboard. Normal traffic is marked as green circles, and malicious connections show up as pulsing red waves.\n"
            "- **Proxy Flags**: Detects whether the source IP is a VPN, Tor exit node, or open proxy."
        ),
        ("intel", "threat_intel", "abuseipdb", "reputation", "score"): (
            "**🔍 Global Threat Intelligence (threat_intel.py)**\n\n"
            "This module cross-references IPs with global threat intelligence databases:\n\n"
            "- **AbuseIPDB**: If configured, it queries the AbuseIPDB API in the background to fetch a reputation score, report count, and proxy flag for external IPs.\n"
            "- **Caching**: Stores resolved IP details in memory to prevent exceeding API limits."
        ),
        ("pcap", "export", "wireshark", "pcap_exporter", "packets"): (
            "**🔬 PCAP Exporter & Forensic Buffer (pcap_exporter.py)**\n\n"
            "For forensic analysis, CyberGuard retains a rolling in-memory buffer of captured raw network packets:\n\n"
            "- Clicking the **Export PCAP** button compiles these packets into a standard `.pcap` file.\n"
            "- You can open this file in **Wireshark** to do deep packet inspection and trace headers, raw payloads, or TCP handshakes."
        ),
        ("setup", "wizard", "config", "configuration", "install", "env"): (
            "**⚙️ Configuration Wizard & Settings**\n\n"
            "System settings are managed dynamically:\n\n"
            "- **Setup Wizard (`setup_wizard.py`)**: An interactive command-line menu to configure network interfaces, bot tokens, email notifications, and AbuseIPDB keys. Saves settings to `.env`.\n"
            "- **Config Manager (`config.py`)**: Loads settings from `.env` at startup to define port list, auto-block thresholds, and alerting channels."
        ),
        ("train", "retrain", "dataset", "training", "train.py"): (
            "**🧠 Model Training Pipeline (train.py)**\n\n"
            "The `backend/train.py` script is used to train CyberGuard's models from scratch:\n\n"
            "- **XGBoost Classifier**: Supervised classification for DDoS, PortScan, and Infiltration.\n"
            "- **Isolation Forest**: Identifies statistical outliers in traffic metrics.\n"
            "- **MLP Autoencoder**: Neural network trained on normal samples only to set reconstruction error anomaly limits.\n"
            "Run `python backend/train.py` from an administrator command prompt to train the system."
        ),
        ("csv", "dataset file", "Monday-WorkingHours"): (
            "**📊 CSV Datasets & File Format**\n\n"
            "CSV (Comma-Separated Values) files store tabular metrics data offline. In this project:\n\n"
            "- **CICIDS2017 Dataset**: The raw traffic flows used to train the machine learning models are saved as CSV tables in the `dataset/` folder.\n"
            "- **Features**: Each row inside these files represents a captured network flow containing 78 statistical network fields."
        ),
        ("pdf", "report", "threat report", "export report"): (
            "**📋 PDF Threat Report Generator**\n\n"
            "The **PDF Threat Report** is a document compiling security logs for your system:\n\n"
            "- **Dynamic Compilation**: Renders your active session statistics, detected categories, and honeypot hits in a visual structure.\n"
            "- **Client-Side Export**: Generated instantly using JavaScript's `jspdf` library inside your browser when you click the **'Export Report (PDF)'** button."
        )
    }

    # 1. First, check for EXACT class/file matches
    exact_files = []
    exact_classes = []
    
    for file, info in kb.items():
        base_name = file.replace(".py", "").lower()
        if base_name == query or query == file.lower():
            exact_files.append((file, info))
        for cls_name, cls_info in info["classes"].items():
            if cls_name.lower() == query:
                exact_classes.append((cls_name, file, cls_info))

    if exact_classes:
        name, file, info = exact_classes[0]
        methods_str = "\n".join([f"- **`.{m['name']}({', '.join(m['args'])})`**: {m['docstring'] or 'Method'}" for m in info["methods"]])
        friendly_intro = class_explanations.get(name, f"**🤖 Class: `{name}` (Found in `backend/{file}`)**\n\nThis is a core component of your intrusion detection system.")
        response = (
            f"{friendly_intro}\n\n"
            f"**File Location:** `backend/{file}`\n"
            f"**Class Description:** {info['docstring'] or 'Core CyberGuard module class.'}\n\n"
            f"**Methods Defined in this Class:**\n{methods_str or '- None.'}\n\n"
            "This class is loaded dynamically when the Flask server initializes."
        )
        return response.replace('#', '')
        
    if exact_files:
        file, info = exact_files[0]
        classes_str = ", ".join([f"`{c}`" for c in info["classes"]]) or "None"
        funcs_str = ", ".join([f"`{f['name']}()`" for f in info["functions"]]) or "None"
        friendly_intro = file_explanations.get(file, f"**📂 Code File: `backend/{file}`**\n\nThis file contains parts of the CyberGuard security logic.")
        response = (
            f"{friendly_intro}\n\n"
            f"- **Classes defined:** {classes_str}\n"
            f"- **Global functions:** {funcs_str}\n"
            f"- **Imported modules:** {', '.join(set(info['imports'][:12]))}\n\n"
            "This module is scanned live. Any changes you make will be parsed instantly!"
        )
        return response.replace('#', '')

    # 2. Second, check general query terms against FAQ keys
    for keys, resp in faq_responses.items():
        if any(k in query for k in keys):
            return resp

    # 3. Third, check for SUBSTRING class/file matches
    sub_files = []
    sub_classes = []
    
    for file, info in kb.items():
        base_name = file.replace(".py", "").lower()
        if (base_name in query) or (len(query) >= 3 and query in base_name) or (".py" in query and base_name in query):
            sub_files.append((file, info))
        for cls_name, cls_info in info["classes"].items():
            cls_lower = cls_name.lower()
            if (cls_lower in query) or (len(query) >= 3 and query in cls_lower):
                sub_classes.append((cls_name, file, cls_info))

    if sub_classes:
        name, file, info = sub_classes[0]
        methods_str = "\n".join([f"- **`.{m['name']}({', '.join(m['args'])})`**: {m['docstring'] or 'Method'}" for m in info["methods"]])
        friendly_intro = class_explanations.get(name, f"**🤖 Class: `{name}` (Found in `backend/{file}`)**\n\nThis is a core component of your intrusion detection system.")
        response = (
            f"{friendly_intro}\n\n"
            f"**File Location:** `backend/{file}`\n"
            f"**Class Description:** {info['docstring'] or 'Core CyberGuard module class.'}\n\n"
            f"**Methods Defined in this Class:**\n{methods_str or '- None.'}\n\n"
            "This class is loaded dynamically when the Flask server initializes."
        )
        return response.replace('#', '')
        
    if sub_files:
        file, info = sub_files[0]
        classes_str = ", ".join([f"`{c}`" for c in info["classes"]]) or "None"
        funcs_str = ", ".join([f"`{f['name']}()`" for f in info["functions"]]) or "None"
        friendly_intro = file_explanations.get(file, f"**📂 Code File: `backend/{file}`**\n\nThis file contains parts of the CyberGuard security logic.")
        response = (
            f"{friendly_intro}\n\n"
            f"- **Classes defined:** {classes_str}\n"
            f"- **Global functions:** {funcs_str}\n"
            f"- **Imported modules:** {', '.join(set(info['imports'][:12]))}\n\n"
            "This module is scanned live. Any changes you make will be parsed instantly!"
        )
        return response.replace('#', '')

    # 3. Fallback code text search (excluding '#' in results) - ONLY triggered for code-related terms
    is_asking_about_code = any(w in query for w in [
        ".py", ".bat", "code", "file", "class", "function", "def", "import", "variable", "line", "_", "()", "script", "methods", "api", "route"
    ])
    
    if is_asking_about_code:
        results = []
        backend_dir = os.path.join(root_dir, "backend")
        if os.path.exists(backend_dir):
            for file in os.listdir(backend_dir):
                if file.endswith(".py"):
                    path = os.path.join(backend_dir, file)
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            lines = f.readlines()
                        for idx, line in enumerate(lines):
                            # Match term and ensure we extract comments or relevant lines
                            if any(term in line.lower() for term in query.split()) and len(line.strip()) > 3:
                                cleaned_line = line.strip().replace('#', '').strip()
                                if cleaned_line:
                                    results.append((file, idx+1, cleaned_line))
                                if len(results) >= 6:
                                    break
                    except Exception:
                        pass
                    
        if results:
            res_str = "\n".join([f"- **`backend/{r[0]}` (Line {r[1]}):** {r[2]}" for r in results])
            response = (
                "**🔍 Live Codebase Search References**\n\n"
                "I scanned the project files and found these relevant lines of code or comments:\n\n"
                f"{res_str}\n\n"
                "Let me know if you would like me to explain any of these files or modules like **detector**, **sniffer**, **blocker**, or **app** in detail!"
            )
            return response.replace('#', '')
        
    # Default Help Response (Zero '#' characters)
    return (
        "**🧠 CyberGuard Security Copilot**\n\n"
        "I scanned your codebase live, but I couldn't find a direct match for your question. I am here to help you understand every part of your project! You can ask me about:\n\n"
        "- **Code Modules**: e.g., `app.py`, `detector.py`, `sniffer.py`, `blocker.py`, `flow_tracker.py`\n"
        "- **Program Classes**: e.g., `EnsembleDetector`, `PacketSniffer`, `AutoBlocker`\n"
        "- **Settings & Config**: e.g., config settings, telegram alerts, honeypot ports\n"
        "- **Security Concepts**: e.g., what is `scapy`?, what is `ids`?, explain `DDoS` or `PortScan`\n\n"
        "Please ask your question again with different keywords, and I'll do my best to assist you!"
    )
