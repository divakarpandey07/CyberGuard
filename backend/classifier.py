import logging, config
logger = logging.getLogger("CyberGuard.Classifier")

def _rule_dos(f, ml):
    fps=f.get("flow_packets_s",0); bps=f.get("flow_bytes_s",0)
    syn=f.get("syn_flag_count",0); ack=f.get("ack_flag_count",0)
    dur=f.get("flow_duration",1e6)/1e6; rst=f.get("rst_flag_count",0)
    if syn>100 and ack<syn*0.1 and dur<5: return "DoS/DDoS"
    if fps>50000 or bps>100_000_000: return "DoS/DDoS"
    if rst>200 and dur<10: return "DoS/DDoS"
    return None

def _rule_portscan(f, ml):
    nf=f.get("total_fwd_packets",0); nb=f.get("total_backward_packets",0)
    syn=f.get("syn_flag_count",0); fm=f.get("fwd_packet_length_mean",0)
    if nf>20 and nb<3 and fm<100: return "PortScan"
    if syn>30 and nb<5: return "PortScan"
    return None

def _rule_infiltration(f, ml):
    nb=f.get("total_backward_packets",0); nf=f.get("total_fwd_packets",0)
    bb=f.get("total_length_bwd_packets",0); fb=f.get("total_length_fwd_packets",0)
    if bb>fb*15 and nb>10: return "Infiltration"
    return None

RULES=[_rule_dos,_rule_portscan,_rule_infiltration]

class AttackClassifier:
    SEVERITY={
        "Normal":("LOW","✅"),"DoS/DDoS":("CRITICAL","🔴"),
        "PortScan":("MEDIUM","🟡"),"Infiltration":("HIGH","🟠"),
        "Anomaly":("MEDIUM","⚠️"),"Zero-Day":("CRITICAL","⚡"),"DNS Attack":("MEDIUM","🌐"),
    }
    RECS={
        "DoS/DDoS":"Rate-limit or block source IP; alert NOC immediately.",
        "PortScan":"Enable IDS port-scan alerts; review firewall ingress rules.",
        "Infiltration":"Audit auth logs; isolate host; check for credential reuse.",
        "Anomaly":"Inspect traffic manually; consider temporary IP block.",
        "Zero-Day":"Unknown attack pattern. Isolate host immediately and investigate.",
        "DNS Attack":"Check DNS resolver logs; block suspicious domains.",
        "Normal":"No action required.",
    }
    def classify(self, features, ml_result):
        rule_label=None
        for rule in RULES:
            rule_label=rule(features,ml_result)
            if rule_label: break
        ml_label=ml_result.get("label","Normal")
        ml_conf=ml_result.get("confidence",0.0)
        is_attack=ml_result.get("is_attack",False)
        if rule_label and is_attack: final=rule_label
        elif rule_label and not is_attack and ml_conf<0.70: final=rule_label
        else: final=ml_label
        sev,icon=self.SEVERITY.get(final,("LOW","ℹ️"))
        return {"label":final,"severity":sev,"severity_icon":icon,
                "confidence":ml_conf,"is_attack":(final!="Normal"),
                "rule_triggered":bool(rule_label),
                "recommendation":self.RECS.get(final,""),
                "ml_label":ml_label,"scores":ml_result.get("scores",{})}
