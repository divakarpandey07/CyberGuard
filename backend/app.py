"""
app.py – CyberGuard IDS v4 Main Server
New in v3: GeoIP map, Telegram/Email alerts, Honeypot,
           Zero-Day autoencoder, Behavioral profiling,
           Online learning, Threat Intel, DNS detection, PCAP export.
ALL FREE — No subscriptions required.
"""
import os, sys, time, json, threading, logging, tempfile
from datetime import datetime
from typing import Optional

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit

sys.path.insert(0, os.path.dirname(__file__))
import config
from flow_tracker          import FlowTracker
from detector              import EnsembleDetector
from classifier            import AttackClassifier
from blocker               import AutoBlocker
from logger_module         import AlertLogger
from sniffer               import PacketSniffer

# ── NEW v3 modules ──────────────────────────────────────────────────────────
from geo_mapper            import GeoMapper
from alerting              import AlertManager
from honeypot              import HoneypotManager
from behavioral_profiler   import BehavioralProfiler
from autoencoder_detector  import AutoencoderDetector
from online_learner        import OnlineLearner
from threat_intel          import ThreatIntelChecker
from dns_detector          import DNSDetector
from pcap_exporter         import PcapExporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-26s │ %(levelname)-7s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("CyberGuard.App")

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.secret_key = config.SECRET_KEY
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                    logger=False, engineio_logger=False)

# ── Core components ─────────────────────────────────────────────────────────
detector   = EnsembleDetector()
classifier = AttackClassifier()
blocker    = AutoBlocker()
alogger    = AlertLogger()
tracker    = FlowTracker()
sniffer    : Optional[PacketSniffer] = None
_sniffer_running = False

# ── v3 components ────────────────────────────────────────────────────────────
geo        = GeoMapper()
alertmgr   = AlertManager()
behavior   = BehavioralProfiler()
ae_detect  = AutoencoderDetector()
online_lrn = OnlineLearner()
threat_int = ThreatIntelChecker()

def _on_dns_alert(ev):
    socketio.emit("dns_event", ev)
    cls = {
        "label": f"DNS Attack ({ev['attack_type']})",
        "severity": ev["severity"],
        "confidence": 1.0,
        "recommendation": f"Inspect DNS query: {ev['query']}. Reason: {ev['reason']}"
    }
    feat = {
        "_src_ip": ev["src_ip"],
        "_dst_ip": ev["query"],
        "_dst_port": "DNS",
        "_geo": geo.lookup(ev["src_ip"]),
        "_ti": threat_int.check(ev["src_ip"])
    }
    alertmgr.send_alert(cls, feat)

dns_det = DNSDetector(alert_callback=_on_dns_alert)
pcap_exp   = PcapExporter()

def _on_honeypot_hit(ev):
    socketio.emit("honeypot_hit", {
        **ev, "timestamp_fmt": datetime.utcnow().strftime("%H:%M:%S")
    })
    cls = {
        "label": f"Honeypot Probe ({ev['service']})",
        "severity": "CRITICAL",
        "confidence": 1.0,
        "recommendation": f"Unauthorized access to fake port {ev['port']} ({ev['service']}). Block IP immediately."
    }
    feat = {
        "_src_ip": ev["src_ip"],
        "_dst_ip": "Honeypot",
        "_dst_port": ev["port"],
        "_geo": geo.lookup(ev["src_ip"]),
        "_ti": threat_int.check(ev["src_ip"])
    }
    alertmgr.send_alert(cls, feat)

honeypot = HoneypotManager(callback=_on_honeypot_hit)


# ── Flow processing ──────────────────────────────────────────────────────────

def _process_flow(features: dict):
    try:
        # 1. ML ensemble prediction
        ml_result = detector.predict(features) if detector.is_ready else {
            "label": "Model Not Loaded", "label_id": -1,
            "confidence": 0.0, "is_attack": False, "scores": {}
        }

        # 2. Rule + ML classifier
        cls_result = classifier.classify(features, ml_result)

        # 3. Zero-Day autoencoder check (overrides if triggered)
        if getattr(config, "AUTOENCODER_ENABLED", True):
            ae_result = ae_detect.predict(features)
            if ae_result["is_zero_day"] and not cls_result["is_attack"]:
                cls_result["label"]          = "Zero-Day"
                cls_result["severity"]       = "CRITICAL"
                cls_result["severity_icon"]  = "⚡"
                cls_result["is_attack"]      = True
                cls_result["recommendation"] = "Possible Zero-Day attack. Isolate host and inspect manually."
            cls_result["ae_score"] = features.get("_simulate_ae_score", ae_result.get("ae_score", 0.0))
        else:
            cls_result["ae_score"] = features.get("_simulate_ae_score", 0.0)

        # 4. Online learning (learn from this flow)
        if online_lrn._ready:
            online_lrn.learn_one(features, ml_result.get("label_id", 0))

        # 5. Behavioral profiling
        profile = behavior.record(features, cls_result["label"])

        # 6. Threat Intelligence check (non-blocking, cached)
        src_ip = features.get("_src_ip", "")
        ti     = threat_int.check(src_ip) if src_ip else {}

        # 7. GeoIP lookup
        geo_info = geo.lookup(src_ip)
        features["_geo"] = geo_info
        features["_ti"]  = ti

        # 8. Log event
        alogger.log_event(cls_result, features)

        # 9. Auto-blocker
        if cls_result["is_attack"]:
            if blocker.record_attack(src_ip, cls_result["label"]) == "blocked":
                cls_result["auto_blocked"] = True
            alertmgr.send_alert(cls_result, features)

        # 10. WebSocket push to dashboard
        payload = {
            "timestamp":      datetime.utcnow().strftime("%H:%M:%S"),
            "src_ip":         src_ip,
            "dst_ip":         features.get("_dst_ip", "?"),
            "dst_port":       features.get("_dst_port", 0),
            "label":          cls_result["label"],
            "severity":       cls_result["severity"],
            "severity_icon":  cls_result["severity_icon"],
            "confidence":     cls_result["confidence"],
            "is_attack":      cls_result["is_attack"],
            "auto_blocked":   cls_result.get("auto_blocked", False),
            "recommendation": cls_result["recommendation"],
            "scores":         cls_result.get("scores", {}),
            "ae_score":       cls_result.get("ae_score", 0.0),
            "hexdump":        features.get("_hexdump", ""),
            "target_geo": {
                "lat": geo._public_geo.get("lat", 0.0),
                "lon": geo._public_geo.get("lon", 0.0),
                "country": geo._public_geo.get("country", ""),
                "city": geo._public_geo.get("city", ""),
            } if geo._public_geo else None,
            # v3 extras
            "geo":  {
                "country":      geo_info.get("country", "?"),
                "country_code": geo_info.get("country_code", "XX"),
                "city":         geo_info.get("city", ""),
                "lat":          geo_info.get("lat", 0.0),
                "lon":          geo_info.get("lon", 0.0),
                "flag":         geo_info.get("flag", ""),
                "is_proxy":     geo_info.get("is_proxy", False),
            },
            "threat": {
                "abuse_score":   ti.get("abuse_score", 0),
                "is_known_bad":  ti.get("is_known_bad", False),
                "total_reports": ti.get("total_reports", 0),
                "shodan":        ti.get("shodan", {}),
            },
            "behavior": {
                "threat_score": profile.threat_score if profile else 0,
                "risk_level":   profile.risk_level   if profile else "LOW",
            } if profile else {},
        }
        socketio.emit("detection_event", payload)

        total = alogger.get_stats()["total"]
        if total % 10 == 0:
            socketio.emit("stats_update", alogger.get_stats())

    except Exception as e:
        logger.error("Processing error: %s", e, exc_info=True)


def _system_stats_loop():
    import psutil
    try:
        last_counters = psutil.net_io_counters()
        last_sent = last_counters.bytes_sent
        last_recv = last_counters.bytes_recv
    except Exception:
        last_sent = 0
        last_recv = 0
    last_time = time.time()
    
    while True:
        try:
            time.sleep(2)
            now = time.time()
            dt = now - last_time
            if dt <= 0:
                dt = 1.0
            
            try:
                curr_counters = psutil.net_io_counters()
                curr_sent = curr_counters.bytes_sent
                curr_recv = curr_counters.bytes_recv
            except Exception:
                curr_sent = last_sent
                curr_recv = last_recv
                
            sent_diff = curr_sent - last_sent
            recv_diff = curr_recv - last_recv
            
            last_sent = curr_sent
            last_recv = curr_recv
            last_time = now
            
            # Speeds in KB/s
            upload_speed = round((sent_diff / 1024.0) / dt, 1)
            download_speed = round((recv_diff / 1024.0) / dt, 1)
            
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            socketio.emit("system_stats", {
                "cpu": cpu,
                "ram": ram,
                "upload_speed": upload_speed,
                "download_speed": download_speed
            })
        except Exception:
            pass


def _processing_loop():
    while True:
        for features in tracker.get_completed_flows():
            _process_flow(features)
        time.sleep(0.5)


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api/health")
def health():
    meta = detector.metadata
    return jsonify({
        "status":            "ok",
        "model_ready":       detector.is_ready,
        "autoencoder_ready": ae_detect.is_ready,
        "online_learner":    online_lrn.get_stats(),
        "dataset":           meta.get("dataset", "Not trained"),
        "test_accuracy":     f"{meta.get('test_accuracy', meta.get('cv_accuracy_mean',0))*100:.2f}%",
        "test_f1":           f"{meta.get('test_f1_weighted', meta.get('cv_f1_mean',0))*100:.2f}%",
        "cv_accuracy":       f"{meta.get('cv_accuracy_mean',0)*100:.2f}%",
        "cv_f1":             f"{meta.get('cv_f1_mean',0)*100:.2f}%",
        "n_train_samples":   meta.get("n_samples", 0),
        "trained_at":        meta.get("trained_at", "N/A"),
        "sniffer_active":    _sniffer_running,
        "honeypot_ports":    honeypot._active_ports,
        "geoip_stats":       geo.stats,
        "threat_intel":      {"api_calls": threat_int.api_calls_today},
        "timestamp":         datetime.utcnow().isoformat(),
    })


@app.route("/api/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True, silent=True) or {}
    if not data:
        return jsonify({"error": "No JSON body"}), 400
    
    # Process the flow fully (logs, alerts, websocket, etc.)
    _process_flow(data)
    
    # Get the classification for response, fallback gracefully if not ready
    ml  = detector.predict(data) if detector.is_ready else {
        "label": "Model Not Loaded", "label_id": -1,
        "confidence": 0.0, "is_attack": False, "scores": {}
    }
    cls = classifier.classify(data, ml)
    ae  = ae_detect.predict(data) if ae_detect.is_ready else {"is_zero_day": False}
    cls["ae_result"] = ae
    return jsonify(cls)


@app.route("/api/logs")
def get_logs():
    n = min(int(request.args.get("n", 100)), 500)
    return jsonify(alogger.get_recent_logs(n))


@app.route("/api/stats")
def get_stats():
    s = alogger.get_stats()
    s["blocked_count"]    = len(blocker.get_blocked_list())
    s["model_accuracy"]   = detector.metadata.get("cv_accuracy_mean", 0)
    s["packets_captured"] = sniffer.packet_count if sniffer else 0
    s["honeypot"]         = honeypot.get_stats()
    s["behavior_summary"] = behavior.get_summary()
    s["dns_stats"]        = dns_det.get_stats()
    s["pcap_buffer"]      = pcap_exp.buffer_size
    return jsonify(s)


@app.route("/api/blocked")
def get_blocked():
    return jsonify(blocker.get_blocked_list())


@app.route("/api/block", methods=["POST"])
def manual_block():
    ip = (request.get_json(force=True) or {}).get("ip", "")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    ok = blocker.block_ip_manual(ip)
    if ok:
        return jsonify({"status": "blocked", "ip": ip})
    return jsonify({"error": "IP is whitelisted or block failed"}), 400


@app.route("/api/unblock", methods=["POST"])
def manual_unblock():
    ip = (request.get_json(force=True) or {}).get("ip", "")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    ok = blocker.unblock_ip(ip)
    return jsonify({"status": "unblocked" if ok else "not_blocked", "ip": ip})


@app.route("/api/export")
def export_logs():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
    tmp.close()
    alogger.export_csv(tmp.name)
    return send_file(
        tmp.name, as_attachment=True,
        download_name=f"cyberguard_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
        mimetype="text/csv",
    )


@app.route("/api/export/pcap", methods=["POST"])
def export_pcap():
    path = pcap_exp.export()
    if not path:
        return jsonify({"error": "PCAP buffer empty or Scapy unavailable"}), 400
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(path),
                     mimetype="application/vnd.tcpdump.pcap")


@app.route("/api/pcap/list")
def list_pcaps():
    return jsonify(pcap_exp.list_exports())


@app.route("/api/geo/<ip>")
def geo_lookup(ip):
    return jsonify(geo.lookup(ip))


@app.route("/api/threat/<ip>")
def threat_lookup(ip):
    return jsonify(threat_int.check(ip))


@app.route("/api/behavior")
def get_behavior():
    return jsonify({
        "top_threats": behavior.get_top_threats(20),
        "summary":     behavior.get_summary(),
    })


@app.route("/api/behavior/<ip>")
def get_behavior_ip(ip):
    return jsonify(behavior.get_profile(ip))


@app.route("/api/honeypot")
def get_honeypot():
    return jsonify({
        "stats": honeypot.get_stats(),
        "hits":  honeypot.get_hits(50),
    })


@app.route("/api/dns")
def get_dns():
    return jsonify({
        "stats":  dns_det.get_stats(),
        "events": dns_det.get_events(50),
    })


@app.route("/api/simulate", methods=["POST"])
def simulate_attack():
    data = request.get_json(force=True, silent=True) or {}
    attack_type = data.get("type", "ddos")
    
    # Define source IPs to demonstrate geo map plotting
    ips = {
        "ddos": "95.213.255.1",          # Russia
        "portscan": "210.140.10.1",       # Japan
        "infiltration": "46.38.251.1",     # Germany
        "zeroday": "185.220.101.5",        # Iceland (Tor exit node)
        "dns": "198.51.100.12"             # US Proxy
    }
    src_ip = ips.get(attack_type, "104.244.42.1") # default US
    
    # Build feature template
    features = {n: 0.0 for n in config.FEATURE_NAMES}
    features["_src_ip"] = src_ip
    features["_dst_ip"] = "192.168.1.50"
    
    if attack_type == "ddos":
        features["_simulate_label"] = "DoS/DDoS"
        features["syn_flag_count"] = 150.0
        features["ack_flag_count"] = 5.0
        features["flow_duration"] = 2.0 * 1e6
        features["flow_packets_s"] = 60000.0
        features["_dst_port"] = 80
        features["_hexdump"] = "0000  00 15 5d 01 0a 02 00 15  5d 01 0a 01 08 00 45 00  ..].....].....E.\n0010  00 28 3f bd 40 00 80 06  e5 4e 5f d5 ff 01 c0 a8  .(?.@....N_.....\n0020  01 32 00 50 14 e6 00 00  00 00 00 00 00 00 50 02  .2.P..........P.\n0030  20 00 5f e2 00 00                                 . ._..."
    elif attack_type == "portscan":
        features["_simulate_label"] = "PortScan"
        features["syn_flag_count"] = 45.0
        features["total_backward_packets"] = 2.0
        features["_dst_port"] = 22
        features["_hexdump"] = "0000  00 15 5d 01 0a 02 00 15  5d 01 0a 01 08 00 45 00  ..].....].....E.\n0010  00 28 1c a2 40 00 80 06  08 6a d2 8c 0a 01 c0 a8  .(..@....j......\n0020  01 32 00 16 9c a4 00 00  00 00 00 00 00 00 50 02  .2............P.\n0030  20 00 a2 b3 00 00                                 . ...."
    elif attack_type == "infiltration":
        features["_simulate_label"] = "Infiltration"
        features["total_length_bwd_packets"] = 50000.0
        features["total_length_fwd_packets"] = 1000.0
        features["total_backward_packets"] = 15.0
        features["_dst_port"] = 443
        features["_hexdump"] = "0000  00 15 5d 01 0a 02 00 15  5d 01 0a 01 08 00 45 00  ..].....].....E.\n0010  01 48 2a bc 40 00 40 06  7b fd 2e 26 fb 01 c0 a8  .H*.@.@.{..&....\n0020  01 32 01 bb d4 31 00 00  00 00 00 00 00 00 80 18  .2...1..........\n0030  01 00 a3 f0 00 00 01 01  08 0a 38 a1 f3 bd 00 0c  ..........8....."
    elif attack_type == "zeroday":
        features["_simulate_label"] = "Zero-Day"
        features["_simulate_ae_score"] = 0.92
        features["_dst_port"] = 8080
        features["_hexdump"] = "0000  00 15 5d 01 0a 02 00 15  5d 01 0a 01 08 00 45 00  ..].....].....E.\n0010  00 3c 1a fd 40 00 40 06  bd 42 b9 dc 65 05 c0 a8  .<..@.@..B..e...\n0020  01 32 1f 90 00 50 00 00  00 00 00 00 00 00 a0 02  .2...P..........\n0030  72 10 3a f1 00 00 02 04  05 b4 04 02 08 0a 1d 2b  r.:............+\n0040  6e a0 00 00 00 00 01 03  03 07                    n........."
    elif attack_type == "dns":
        import time as _time
        ev = {
            "attack_type": "DNS Tunneling",
            "label":       "DNS Attack",
            "src_ip":      src_ip,
            "query":       "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.malicious-c2-channel.com",
            "reason":      "subdomain length 40",
            "severity":    "HIGH",
            "timestamp":   _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime(_time.time())),
        }
        logs = [
            "[SIMULATOR] Initializing outbound DGA lookup simulation...",
            "[SIMULATOR] Resolving DNS query through default network socket...",
            "[SIMULATOR] Query payload: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.malicious-c2-channel.com",
            "[SIMULATOR] Target sub-domain entropy: 4.12, length: 40 bytes...",
            "[SIMULATOR] DNS Tunneling signature identified by heuristic parser...",
            "[SIMULATOR] Dispatched High Severity alert event to notification manager...",
            "[SIMULATOR] Simulation completed. Check DNS tab dashboard telemetry."
        ]
        with dns_det._lock:
            dns_det._attacks += 1
            dns_det._total += 1
            dns_det._events.append(ev)
            if len(dns_det._events) > 500:
                dns_det._events = dns_det._events[-500:]
        threading.Thread(target=_on_dns_alert, args=(ev,), daemon=True).start()
        return jsonify({"status": "success", "simulated": attack_type, "src_ip": src_ip, "logs": logs})
        
    logs_map = {
        "ddos": [
            "[SIMULATOR] Initializing DDoS threat vector simulation...",
            "[SIMULATOR] Selecting high-speed target interface adapter...",
            "[SIMULATOR] Crafting 150 target TCP packets with SYN flags...",
            "[SIMULATOR] Generating high flow packet velocity: 60,000 packets/sec...",
            f"[SIMULATOR] Transmitting flood payload from IP {src_ip} to destination port 80...",
            "[SIMULATOR] Injecting flow features into ML classifier pipeline...",
            "[SIMULATOR] Simulation completed. Checking dashboard alert logs."
        ],
        "portscan": [
            "[SIMULATOR] Commencing stealth network mapping scan simulation...",
            "[SIMULATOR] Crafting 45 SYN probe packets...",
            "[SIMULATOR] Probing local port range, targeted port 22 (SSH)...",
            f"[SIMULATOR] Transmitting probe packets from host {src_ip}...",
            "[SIMULATOR] Flow reassembled. Forwarding features to XGBoost classifier...",
            "[SIMULATOR] Simulation completed. Check PortScan alerts on dashboard."
        ],
        "infiltration": [
            "[SIMULATOR] Initializing remote command injection simulation...",
            "[SIMULATOR] Simulating privilege escalation and shell breakout attempts...",
            "[SIMULATOR] Establishing outbound command & control socket tunnel on port 443...",
            f"[SIMULATOR] Simulating exfiltration of 50,000 bytes payload to {src_ip}...",
            "[SIMULATOR] Infiltration signature loaded into classification pipeline...",
            "[SIMULATOR] Simulation completed. Check Infiltration events."
        ],
        "zeroday": [
            "[SIMULATOR] Initializing zero-day anomaly injection simulation...",
            "[SIMULATOR] Crafting novel shellcode payload targeted at port 8080...",
            f"[SIMULATOR] Sending packets from Iceland Tor Exit node {src_ip}...",
            "[SIMULATOR] Submitting reassembled flow features to PyTorch Autoencoder...",
            "[SIMULATOR] Reconstruction error calculated at 0.92 (Anomaly threshold: 0.55)...",
            "[SIMULATOR] Zero-Day classification override triggered. Check anomaly log."
        ]
    }
    logs = logs_map.get(attack_type, ["[SIMULATOR] Unknown simulation type triggered."])
    threading.Thread(target=_process_flow, args=(features,), daemon=True).start()
    return jsonify({"status": "success", "simulated": attack_type, "src_ip": src_ip, "logs": logs})


@app.route("/api/ai/ask", methods=["POST"])
def ai_ask():
    data = request.get_json(force=True, silent=True) or {}
    query = data.get("query", "")
    if not query:
        return jsonify({"error": "No query provided"}), 400
    
    import ai_analyst
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    response = ai_analyst.answer_query(query, project_root)
    return jsonify({"response": response})


def save_settings_to_env(settings_dict):
    env_path = os.path.join(config.ROOT_DIR, ".env")
    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
    existing_keys = {}
    for idx, line in enumerate(lines):
        clean_line = line.strip()
        if clean_line and not clean_line.startswith("#") and "=" in clean_line:
            parts = clean_line.split("=", 1)
            k = parts[0].strip()
            existing_keys[k] = idx
            
    for key, val in settings_dict.items():
        if isinstance(val, bool):
            val_str = "true" if val else "false"
        else:
            val_str = str(val)
            
        if key in existing_keys:
            idx = existing_keys[key]
            orig = lines[idx]
            suffix = "\r\n" if orig.endswith("\r\n") else "\n"
            lines[idx] = f"{key}={val_str}{suffix}"
        else:
            lines.append(f"{key}={val_str}\n")
            
    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(lines)


@app.route("/api/settings", methods=["GET"])
def get_settings():
    ifaces_list = []
    try:
        from scapy.all import conf
        for name, iface in conf.ifaces.items():
            ifaces_list.append({
                "name": iface.name,
                "description": getattr(iface, "description", iface.name),
                "ip": getattr(iface, "ip", "No IP")
            })
    except Exception:
        try:
            from scapy.all import get_if_list
            for name in get_if_list():
                ifaces_list.append({
                    "name": name,
                    "description": name,
                    "ip": "No IP"
                })
        except Exception:
            pass

    return jsonify({
        "AUTO_BLOCK_ENABLED": config.AUTO_BLOCK_ENABLED,
        "BLOCK_THRESHOLD": config.BLOCK_THRESHOLD,
        "BLOCK_DURATION": config.BLOCK_DURATION,
        "TELEGRAM_ENABLED": config.TELEGRAM_ENABLED,
        "TELEGRAM_BOT_TOKEN": config.TELEGRAM_BOT_TOKEN,
        "TELEGRAM_CHAT_ID": config.TELEGRAM_CHAT_ID,
        "EMAIL_ENABLED": config.EMAIL_ENABLED,
        "ALERT_EMAIL_FROM": config.EMAIL_SENDER,
        "ALERT_EMAIL_PASS": config.EMAIL_PASSWORD,
        "ALERT_EMAIL_TO": config.EMAIL_RECIPIENT,
        "ABUSEIPDB_KEY": config.ABUSEIPDB_API_KEY,
        "AUTOENCODER_ENABLED": config.AUTOENCODER_ENABLED,
        "ANOMALY_DETECTION_ENABLED": config.ANOMALY_DETECTION_ENABLED,
        "ONLINE_LEARNING_ENABLED": config.ONLINE_LEARNING_ENABLED,
        "INTERFACE": config.INTERFACE,
        "interfaces": ifaces_list,
        "current_interface": sniffer._iface if (sniffer and sniffer.is_running) else config.INTERFACE
    })


@app.route("/api/settings", methods=["POST"])
def post_settings():
    global sniffer, _sniffer_running
    data = request.get_json(force=True, silent=True) or {}
    
    # Update variables in-memory
    config.TELEGRAM_ENABLED = bool(data.get("TELEGRAM_ENABLED", config.TELEGRAM_ENABLED))
    config.TELEGRAM_BOT_TOKEN = str(data.get("TELEGRAM_BOT_TOKEN", config.TELEGRAM_BOT_TOKEN))
    config.TELEGRAM_CHAT_ID = str(data.get("TELEGRAM_CHAT_ID", config.TELEGRAM_CHAT_ID))
    
    config.EMAIL_ENABLED = bool(data.get("EMAIL_ENABLED", config.EMAIL_ENABLED))
    config.EMAIL_SENDER = str(data.get("ALERT_EMAIL_FROM", config.EMAIL_SENDER))
    config.EMAIL_PASSWORD = str(data.get("ALERT_EMAIL_PASS", config.EMAIL_PASSWORD))
    config.EMAIL_RECIPIENT = str(data.get("ALERT_EMAIL_TO", config.EMAIL_RECIPIENT))
    
    config.AUTO_BLOCK_ENABLED = bool(data.get("AUTO_BLOCK_ENABLED", config.AUTO_BLOCK_ENABLED))
    try:
        config.BLOCK_THRESHOLD = int(data.get("BLOCK_THRESHOLD", config.BLOCK_THRESHOLD))
    except Exception:
        pass
    try:
        config.BLOCK_DURATION = int(data.get("BLOCK_DURATION", config.BLOCK_DURATION))
    except Exception:
        pass
        
    config.ABUSEIPDB_API_KEY = str(data.get("ABUSEIPDB_KEY", config.ABUSEIPDB_API_KEY))
    config.AUTOENCODER_ENABLED = bool(data.get("AUTOENCODER_ENABLED", config.AUTOENCODER_ENABLED))
    config.ANOMALY_DETECTION_ENABLED = bool(data.get("ANOMALY_DETECTION_ENABLED", config.ANOMALY_DETECTION_ENABLED))
    config.ONLINE_LEARNING_ENABLED = bool(data.get("ONLINE_LEARNING_ENABLED", config.ONLINE_LEARNING_ENABLED))
    
    new_interface = data.get("INTERFACE", config.INTERFACE)
    interface_changed = (new_interface != config.INTERFACE)
    config.INTERFACE = new_interface
    
    # Save back to .env
    env_payload = {
        "TELEGRAM_ENABLED": config.TELEGRAM_ENABLED,
        "TELEGRAM_BOT_TOKEN": config.TELEGRAM_BOT_TOKEN,
        "TELEGRAM_CHAT_ID": config.TELEGRAM_CHAT_ID,
        "EMAIL_ENABLED": config.EMAIL_ENABLED,
        "ALERT_EMAIL_FROM": config.EMAIL_SENDER,
        "ALERT_EMAIL_PASS": config.EMAIL_PASSWORD,
        "ALERT_EMAIL_TO": config.EMAIL_RECIPIENT,
        "AUTO_BLOCK_ENABLED": config.AUTO_BLOCK_ENABLED,
        "BLOCK_THRESHOLD": config.BLOCK_THRESHOLD,
        "BLOCK_DURATION": config.BLOCK_DURATION,
        "ABUSEIPDB_KEY": config.ABUSEIPDB_API_KEY,
        "AUTOENCODER_ENABLED": config.AUTOENCODER_ENABLED,
        "ANOMALY_DETECTION_ENABLED": config.ANOMALY_DETECTION_ENABLED,
        "ONLINE_LEARNING_ENABLED": config.ONLINE_LEARNING_ENABLED,
        "INTERFACE": config.INTERFACE or ""
    }
    
    try:
        save_settings_to_env(env_payload)
    except Exception as e:
        logger.error("Failed to write settings to .env: %s", e)
        
    if interface_changed and _sniffer_running and sniffer:
        logger.info("Restarting sniffer on new interface: %s", new_interface)
        try:
            sniffer.stop()
        except Exception:
            pass
        sniffer = PacketSniffer(callback=tracker.add_packet,
                                dns_callback=dns_det.process_packet,
                                pcap_callback=pcap_exp.add_packet)
        sniffer.start()
        socketio.emit("sniffer_status", {
            "active": True,
            "interface": sniffer._iface,
            "ip": getattr(sniffer, "_ip", None)
        })
        
    return jsonify({"status": "success", "note": "Configuration saved to .env and applied!"})


@app.route("/api/ai/audit", methods=["POST"])
def ai_audit():
    import psutil, ai_analyst
    
    # Gather diagnostics
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    total_flows = tracker.get_total_flows_count() if hasattr(tracker, 'get_total_flows_count') else len(tracker._flows) if hasattr(tracker, '_flows') else 0
    if total_flows == 0:
        total_flows = alogger.get_stats().get("total", 0)
        
    attacks_detected = alogger.get_stats().get("attacks", 0)
    ips_blocked = len(blocker.get_blocked_list())
    
    honeypot_active = config.HONEYPOT_ENABLED
    honeypot_hits = len(honeypot._hits) if hasattr(honeypot, '_hits') else 0
    
    dns_stats = dns_det.get_stats() if hasattr(dns_det, 'get_stats') else {}
    dns_queries = dns_stats.get("total_dns_queries", 0)
    dns_attacks = dns_stats.get("dns_attacks", 0)
    
    tg_enabled = config.TELEGRAM_ENABLED
    email_enabled = config.EMAIL_ENABLED
    intel_active = bool(config.ABUSEIPDB_API_KEY)
    
    ml_ready = detector.is_ready
    ml_accuracy = detector.metadata.get("test_accuracy", 0.0) if detector.is_ready else 0.0
    ae_ready = ae_detect.is_ready
    online_learning = config.ONLINE_LEARNING_ENABLED
    auto_block = config.AUTO_BLOCK_ENABLED
    active_interface = sniffer._iface if (sniffer and sniffer.is_running) else config.INTERFACE or "Default Auto-Detect"
    
    audit_payload = {
        "cpu": cpu,
        "ram": ram,
        "total_flows": total_flows,
        "attacks_detected": attacks_detected,
        "ips_blocked": ips_blocked,
        "honeypot_active": honeypot_active,
        "honeypot_hits": honeypot_hits,
        "dns_queries": dns_queries,
        "dns_attacks": dns_attacks,
        "tg_enabled": tg_enabled,
        "email_enabled": email_enabled,
        "intel_active": intel_active,
        "ml_ready": ml_ready,
        "ml_accuracy": ml_accuracy,
        "ae_ready": ae_ready,
        "online_learning": online_learning,
        "auto_block": auto_block,
        "active_interface": active_interface
    }
    
    import json
    query = f"[audit_data] {json.dumps(audit_payload)}"
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report = ai_analyst.answer_query(query, project_root)
    return jsonify({"report": report})


@app.route("/api/sniffer", methods=["POST"])
def sniffer_control():
    global sniffer, _sniffer_running
    action = (request.get_json(force=True) or {}).get("action", "")
    if action == "start":
        if not _sniffer_running:
            sniffer = PacketSniffer(callback=tracker.add_packet,
                                    dns_callback=dns_det.process_packet,
                                    pcap_callback=pcap_exp.add_packet)
            sniffer.start()
            _sniffer_running = True
            socketio.emit("sniffer_status", {
                "active": True,
                "interface": sniffer._iface,
                "ip": getattr(sniffer, "_ip", None)
            })
        return jsonify({"status": "started"})
    elif action == "stop":
        if _sniffer_running and sniffer:
            sniffer.stop()
            _sniffer_running = False
            socketio.emit("sniffer_status", {"active": False})
        return jsonify({"status": "stopped"})
    return jsonify({"error": "action: start or stop"}), 400


@app.route("/api/alert/test/telegram", methods=["POST"])
def test_telegram():
    ok = alertmgr.test_telegram()
    return jsonify({"success": ok,
                    "note": "Check config.py TELEGRAM_ENABLED / BOT_TOKEN / CHAT_ID"})


@app.route("/api/alert/test/email", methods=["POST"])
def test_email():
    ok = alertmgr.test_email()
    return jsonify({"success": ok,
                    "note": "Check config.py EMAIL_ENABLED / EMAIL_SENDER / EMAIL_PASSWORD"})


@socketio.on("connect")
def on_connect():
    emit("sniffer_status", {
        "active": _sniffer_running,
        "interface": sniffer._iface if sniffer else None,
        "ip": getattr(sniffer, "_ip", None) if sniffer else None
    })
    emit("stats_update",   alogger.get_stats())
    if detector.is_ready:
        meta_full = {**detector.metadata,
                     "test_accuracy": detector.metadata.get("test_accuracy",
                                      detector.metadata.get("cv_accuracy_mean", 0))}
        emit("model_info", meta_full)


# ── Startup ───────────────────────────────────────────────────────────────────

def _startup():
    os.makedirs(config.LOG_DIR,  exist_ok=True)
    os.makedirs(config.PCAP_DIR, exist_ok=True)

    # Load models
    if not detector.load_models():
        logger.warning(
            "\n  ⚠️  Models not found.\n"
            "  Step 1: python backend/download_dataset.py\n"
            "  Step 2: python backend/train.py\n"
        )
    ae_detect.load()

    # Start honeypot
    active_ports = honeypot.start()
    if active_ports:
        logger.info("🍯 Honeypot listening on: %s", active_ports)

    # Live capture is started manually from the dashboard
    logger.info("ℹ️ Live capture ready. Open the dashboard and click [▶ Start Capture] to begin.")

    # Start processing loop
    threading.Thread(target=_processing_loop, daemon=True, name="ProcessingLoop").start()
    # Start system stats loop
    threading.Thread(target=_system_stats_loop, daemon=True, name="SystemStatsLoop").start()

    logger.info("=" * 60)
    logger.info("🛡️  CyberGuard IDS v4 → http://%s:%d", config.HOST, config.PORT)
    logger.info("   Whitelist: %s (Will never be blocked)", config.WHITELIST_IPS)
    logger.info("   GeoIP    : %s", "ON" if config.GEOIP_ENABLED else "OFF")
    logger.info("   Telegram : %s", "ON" if config.TELEGRAM_ENABLED else "OFF (see config.py)")
    logger.info("   Email    : %s", "ON" if config.EMAIL_ENABLED else "OFF (see config.py)")
    logger.info("   Honeypot : %s", "ON" if config.HONEYPOT_ENABLED else "OFF")
    logger.info("   Zero-Day : %s", "ON" if ae_detect.is_ready else "NOT TRAINED (run train.py)")
    logger.info("   Online ML: %s", "ON" if config.ONLINE_LEARNING_ENABLED else "OFF (pip install river)")
    logger.info("=" * 60)


if __name__ == "__main__":
    _startup()
    socketio.run(app, host=config.HOST, port=config.PORT,
                 debug=config.DEBUG, use_reloader=False,
                 allow_unsafe_werkzeug=True)


# optimized server WebSocket event handlers
