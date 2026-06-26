"""
behavioral_profiler.py – Per-IP behavioral profiling & threat scoring
FREE: Pure Python, zero external dependencies.
Tracks connection patterns per IP over sliding windows.
Generates 0-100 threat score based on attack ratio, port variety, connection rate.
"""
import time, threading, logging
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import config

logger = logging.getLogger("CyberGuard.Behavior")


@dataclass
class IPProfile:
    ip:            str
    events:        deque = field(default_factory=lambda: deque(maxlen=500))
    labels_seen:   Dict[str, int] = field(default_factory=dict)
    ports_targeted: set = field(default_factory=set)
    bytes_total:   int  = 0
    attack_count:  int  = 0
    normal_count:  int  = 0
    first_seen:    float = field(default_factory=time.time)
    last_seen:     float = field(default_factory=time.time)
    threat_score:  float = 0.0
    risk_level:    str   = "LOW"

    def record(self, features: dict, label: str):
        now = time.time()
        self.last_seen = now
        self.events.appendleft(now)
        self.bytes_total  += features.get("total_length_fwd_packets", 0)
        port = features.get("_dst_port", 0)
        if port:
            self.ports_targeted.add(port)
        self.labels_seen[label] = self.labels_seen.get(label, 0) + 1
        if label == "Normal":
            self.normal_count += 1
        else:
            self.attack_count += 1
        self._compute_threat()

    def _compute_threat(self):
        total = self.attack_count + self.normal_count
        if total == 0:
            self.threat_score = 0.0
            self.risk_level   = "LOW"
            return
        
        # Factor 1: attack ratio (0-1)
        attack_ratio = self.attack_count / total
        
        # Factor 2: port variety (0-1, saturates at 50 ports)
        port_score = min(len(self.ports_targeted) / 50.0, 1.0)
        
        # Factor 3: connection rate in window (0-1, saturates at 100 events)
        cutoff = time.time() - config.BEHAVIOR_WINDOW_SEC
        recent = sum(1 for t in self.events if t > cutoff)
        rate_score = min(recent / 100.0, 1.0)
        
        # Factor 4: zero-day / high severity events
        zeroday = self.labels_seen.get("Zero-Day", 0) + self.labels_seen.get("DoS/DDoS", 0)
        severe_score = min(zeroday / 5.0, 1.0)

        raw = (attack_ratio * 0.45 + port_score * 0.25 + rate_score * 0.20 + severe_score * 0.10)
        self.threat_score = round(raw * 100, 1)

        if   self.threat_score >= 70: self.risk_level = "CRITICAL"
        elif self.threat_score >= 45: self.risk_level = "HIGH"
        elif self.threat_score >= 20: self.risk_level = "MEDIUM"
        else:                          self.risk_level = "LOW"

    def to_dict(self) -> dict:
        # Recent event rate
        cutoff = time.time() - config.BEHAVIOR_WINDOW_SEC
        recent = sum(1 for t in self.events if t > cutoff)
        return {
            "ip":           self.ip,
            "threat_score": self.threat_score,
            "risk_level":   self.risk_level,
            "attack_count": self.attack_count,
            "normal_count": self.normal_count,
            "bytes_total":  self.bytes_total,
            "ports_count":  len(self.ports_targeted),
            "labels":       self.labels_seen,
            "recent_events": recent,
            "first_seen":   round(self.first_seen),
            "last_seen":    round(self.last_seen),
        }


class BehavioralProfiler:
    """Maintains per-IP profiles, evicts stale ones hourly."""

    def __init__(self):
        self._profiles : Dict[str, IPProfile] = {}
        self._lock     = threading.Lock()
        self._running  = True
        threading.Thread(target=self._cleanup, daemon=True, name="BehaviorCleanup").start()

    def record(self, features: dict, label: str) -> Optional[IPProfile]:
        src_ip = features.get("_src_ip", "")
        if not src_ip or src_ip in ("?", "0.0.0.0"):
            return None
        with self._lock:
            if src_ip not in self._profiles:
                # Evict oldest if at capacity
                if len(self._profiles) >= config.BEHAVIOR_MAX_IPS:
                    oldest = min(self._profiles, key=lambda k: self._profiles[k].last_seen)
                    del self._profiles[oldest]
                self._profiles[src_ip] = IPProfile(ip=src_ip)
            p = self._profiles[src_ip]
        p.record(features, label)
        return p

    def get_top_threats(self, n: int = 15) -> List[dict]:
        with self._lock:
            profiles = list(self._profiles.values())
        profiles.sort(key=lambda p: p.threat_score, reverse=True)
        return [p.to_dict() for p in profiles[:n]]

    def get_profile(self, ip: str) -> dict:
        with self._lock:
            p = self._profiles.get(ip)
        return p.to_dict() if p else {}

    def get_summary(self) -> dict:
        with self._lock:
            all_p = list(self._profiles.values())
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for p in all_p:
            risk_counts[p.risk_level] = risk_counts.get(p.risk_level, 0) + 1
        return {
            "total_ips_tracked": len(all_p),
            "risk_breakdown":    risk_counts,
        }

    def stop(self):
        self._running = False

    def _cleanup(self):
        while self._running:
            cutoff = time.time() - 3600  # 1 hour stale
            with self._lock:
                stale = [ip for ip, p in self._profiles.items() if p.last_seen < cutoff]
                for ip in stale:
                    del self._profiles[ip]
            if stale:
                logger.info("Behavior: evicted %d stale profiles", len(stale))
            time.sleep(300)
