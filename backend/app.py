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
        "_dst_port": "DNS"
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
        "_dst_port": ev["port"]
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
            cls_result["ae_score"] = ae_result.get("ae_score", 0.0)
        else:
            cls_result["ae_score"] = 0.0

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
    while True:
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            socketio.emit("system_stats", {
                "cpu": cpu,
                "ram": ram,
            })
        except Exception:
            pass
        time.sleep(2)


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
