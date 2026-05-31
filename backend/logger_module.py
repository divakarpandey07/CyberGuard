
import os,json,time,logging,threading,csv
from collections import deque
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Deque,List
import config

_RESET="[0m";_RED="[91m";_YELLOW="[93m";_GREEN="[92m"
SEVERITY_COLORS={"CRITICAL":_RED+"[1m","HIGH":_RED,"MEDIUM":_YELLOW,"LOW":_GREEN}

def _setup_file_logger(name,filepath):
    os.makedirs(os.path.dirname(filepath),exist_ok=True)
    h=RotatingFileHandler(filepath,maxBytes=config.MAX_LOG_SIZE_MB*1024*1024,
                          backupCount=config.LOG_BACKUP_COUNT,encoding="utf-8")
    h.setFormatter(logging.Formatter("%(message)s"))
    lg=logging.getLogger(name);lg.setLevel(logging.INFO);lg.addHandler(h);lg.propagate=False
    return lg

class AlertLogger:
    MAX_BUFFER=500
    def __init__(self):
        os.makedirs(config.LOG_DIR,exist_ok=True)
        self._attack_logger=_setup_file_logger("attacks",os.path.join(config.LOG_DIR,"attacks.jsonl"))
        self._audit_logger=_setup_file_logger("audit",os.path.join(config.LOG_DIR,"audit.log"))
        self._buffer:Deque[dict]=deque(maxlen=self.MAX_BUFFER)
        self._lock=threading.Lock()
        self._stats={label:0 for label in config.ATTACK_LABELS.values()}
        self._total=0
        self._console=logging.getLogger("CyberGuard")
    def log_event(self,classification,features):
        ts=features.get("_timestamp",time.time())
        src_ip=features.get("_src_ip","?");dst_ip=features.get("_dst_ip","?")
        port=features.get("_dst_port",0);label=classification.get("label","Unknown")
        sev=classification.get("severity","LOW");conf=classification.get("confidence",0.0)
        icon=classification.get("severity_icon","")
        record={"timestamp":datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
                "ts_epoch":round(ts,3),"src_ip":src_ip,"dst_ip":dst_ip,"dst_port":port,
                "label":label,"severity":sev,"confidence":conf,
                "rule_triggered":classification.get("rule_triggered",False),
                "recommendation":classification.get("recommendation",""),
                "scores":classification.get("scores",{})}
        self._attack_logger.info(json.dumps(record))
        with self._lock:
            self._buffer.appendleft(record)
            self._stats[label]=self._stats.get(label,0)+1
            self._total+=1
        if classification.get("is_attack"):
            color=SEVERITY_COLORS.get(sev,"")
            self._console.warning("%s%s [%s] %s -> %s:%d | conf=%.2f%s",
                color,icon,sev,src_ip,dst_ip,port,conf,_RESET)
    def get_recent_logs(self,n=100):
        with self._lock: return list(self._buffer)[:n]
    def get_stats(self):
        with self._lock: return {"total":self._total,"by_type":dict(self._stats)}
    def export_csv(self,filepath):
        with self._lock: entries=list(self._buffer)
        if not entries: return
        with open(filepath,"w",newline="",encoding="utf-8") as f:
            writer=csv.DictWriter(f,fieldnames=[k for k in entries[0] if k!="scores"])
            writer.writeheader()
            for e in entries:
                writer.writerow({k:v for k,v in e.items() if k!="scores"})
