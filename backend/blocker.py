import os, subprocess, threading, time, logging
from collections import defaultdict
from typing import Dict, Optional
import config

logger = logging.getLogger("CyberGuard.Blocker")

class AutoBlocker:
    def __init__(self):
        self._strikes: Dict[str, int] = defaultdict(int)
        self._blocked: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._running = True
        threading.Thread(target=self._auto_unblock_loop, daemon=True).start()

    def record_attack(self, src_ip: str, label: str) -> Optional[str]:
        if not config.AUTO_BLOCK_ENABLED: return None
        if self._is_whitelisted(src_ip): return None
        with self._lock:
            if src_ip in self._blocked: return None
            self._strikes[src_ip] += 1
            if self._strikes[src_ip] >= config.BLOCK_THRESHOLD:
                self._block_ip(src_ip)
                return "blocked"
        return None

    def block_ip_manual(self, ip: str) -> bool:
        if self._is_whitelisted(ip): return False
        with self._lock:
            if ip in self._blocked: return True
            self._block_ip(ip)
            return True

    def unblock_ip(self, ip: str) -> bool:
        with self._lock: return self._unblock_ip(ip)

    def get_blocked_list(self) -> list:
        now = time.time()
        with self._lock:
            return [{"ip": ip, "blocked_at": round(ts),
                     "remaining_sec": max(0, int(config.BLOCK_DURATION-(now-ts)))}
                    for ip, ts in self._blocked.items()]

    def get_strike_count(self, ip): 
        with self._lock: return self._strikes.get(ip, 0)

    def stop(self): self._running = False

    def _block_ip(self, ip):
        if self._apply_firewall_rule(ip, "block"):
            self._blocked[ip] = time.time()
            logger.warning("🔒 BLOCKED: %s", ip)

    def _unblock_ip(self, ip) -> bool:
        if ip not in self._blocked: return False
        if self._apply_firewall_rule(ip, "unblock"):
            del self._blocked[ip]; self._strikes.pop(ip, None)
            logger.info("🔓 UNBLOCKED: %s", ip)
            return True
        return False

    def _auto_unblock_loop(self):
        while self._running:
            now = time.time()
            with self._lock:
                for ip in [ip for ip,ts in list(self._blocked.items())
                           if (now-ts) >= config.BLOCK_DURATION]:
                    self._unblock_ip(ip)
            time.sleep(30)

    @staticmethod
    def _is_whitelisted(ip): return ip in config.WHITELIST_IPS

    @staticmethod
    def _apply_firewall_rule(ip, action) -> bool:
        plat = config.OS_PLATFORM
        name = f"CyberGuard_Block_{ip.replace('.','_')}"
        try:
            if plat == "Windows":
                cmd = (["netsh","advfirewall","firewall","add","rule",
                        f"name={name}","dir=in","action=block",f"remoteip={ip}",
                        "protocol=any","enable=yes"] if action=="block"
                       else ["netsh","advfirewall","firewall","delete","rule",f"name={name}"])
            elif plat == "Linux":
                cmd = (["iptables","-I","INPUT","-s",ip,"-j","DROP"] if action=="block"
                       else ["iptables","-D","INPUT","-s",ip,"-j","DROP"])
            elif plat == "Darwin":
                logger.info("[macOS] Would %s %s", action, ip); return True
            else:
                return False
            return subprocess.run(cmd, capture_output=True, timeout=10).returncode == 0
        except Exception as e:
            logger.error("Firewall error: %s", e); return False
