"""
dns_detector.py – DNS-based Attack Detection
FREE: Pure Python + Scapy (already installed)
Detects:
  1. DNS Tunneling  — abnormally long / high-entropy subdomains
  2. DGA Domains    — algorithmically generated, hard-to-pronounce names
  3. DNS Flood      — excessive query rate from single IP
"""
import re, math, time, threading, logging
from collections import defaultdict, deque
from typing import Dict, List, Optional

logger = logging.getLogger("CyberGuard.DNS")

# Common TLDs to strip before analysis
COMMON_TLDS = {
    "com","net","org","gov","edu","io","co","uk","in","de","fr",
    "au","ca","jp","cn","ru","br","nl","se","no","fi","pl","it",
}

# Consonant clusters that look unpronounceable
_HARD_RE = re.compile(r"[^aeiou]{5,}", re.I)
_HEX_RE  = re.compile(r"^[0-9a-f]{8,}$", re.I)


def _entropy(s: str) -> float:
    """Shannon entropy of a string (0 = all same char, higher = more random)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def _is_dga(domain: str) -> tuple:
    """
    Returns (is_suspicious: bool, reason: str).
    Simple heuristics — catches many DGA families.
    """
    # Strip TLD parts
    parts = domain.lower().rstrip(".").split(".")
    parts = [p for p in parts if p not in COMMON_TLDS and len(p) > 2]
    if not parts:
        return False, ""

    label = parts[-1]    # leftmost meaningful label

    # 1. Hex-looking label (e.g. C2 beacons)
    if _HEX_RE.match(label):
        return True, "hex-pattern label"

    # 2. High Shannon entropy
    ent = _entropy(label)
    if ent > 3.8:
        return True, f"high entropy ({ent:.2f})"

    # 3. Long unpronounceable consonant clusters
    if _HARD_RE.search(label):
        return True, "consonant cluster"

    # 4. Very long label (>= 25 chars)
    if len(label) >= 25:
        return True, f"long label ({len(label)} chars)"

    # 5. Low vowel ratio
    vowels = sum(1 for c in label if c in "aeiou")
    if len(label) > 6 and vowels / len(label) < 0.15:
        return True, "low vowel ratio"

    return False, ""


class DNSDetector:
    """
    Parses DNS layer from Scapy packets.
    Call process_packet() for each captured packet.
    """

    QUERY_RATE_WINDOW = 60     # seconds
    QUERY_RATE_LIMIT  = 200    # queries/window before flood alert
    TUNNEL_LEN_THRESH = 50     # subdomain length for tunneling suspicion

    def __init__(self, alert_callback=None):
        self._callback     = alert_callback
        self._query_times  : Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._events       : List[dict] = []
        self._lock         = threading.Lock()
        self._total        = 0
        self._attacks      = 0

    def process_packet(self, raw_pkt) -> Optional[dict]:
        """
        Pass a Scapy packet. Returns alert dict if attack detected, else None.
        Call from PacketSniffer._process_packet.
        """
        try:
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.inet import IP

            if not (raw_pkt.haslayer(DNS) and raw_pkt.haslayer(DNSQR)):
                return None

            ip_layer = raw_pkt.getlayer(IP)
            src_ip   = ip_layer.src if ip_layer else "?"
            ts       = float(raw_pkt.time)

            with self._lock:
                self._total += 1
                self._query_times[src_ip].appendleft(ts)

            # Extract query name
            qname = raw_pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="replace").rstrip(".")

            alert = None

            # 1. DNS Tunneling: abnormally long subdomain
            subdomain_len = len(qname.split(".")[0]) if "." in qname else len(qname)
            if subdomain_len >= self.TUNNEL_LEN_THRESH:
                alert = self._make_alert(
                    src_ip=src_ip, qname=qname, ts=ts,
                    attack_type="DNS Tunneling",
                    reason=f"subdomain length {subdomain_len}",
                    severity="HIGH",
                )

            # 2. DGA Detection
            elif len(qname) > 4:
                is_dga, reason = _is_dga(qname)
                if is_dga:
                    alert = self._make_alert(
                        src_ip=src_ip, qname=qname, ts=ts,
                        attack_type="DGA Domain",
                        reason=reason,
                        severity="MEDIUM",
                    )

            # 3. DNS Flood
            cutoff = ts - self.QUERY_RATE_WINDOW
            with self._lock:
                recent = sum(1 for t in self._query_times[src_ip] if t >= cutoff)
            if recent >= self.QUERY_RATE_LIMIT:
                alert = self._make_alert(
                    src_ip=src_ip, qname=qname, ts=ts,
                    attack_type="DNS Flood",
                    reason=f"{recent} queries/{self.QUERY_RATE_WINDOW}s",
                    severity="HIGH",
                )

            if alert:
                with self._lock:
                    self._attacks += 1
                    self._events.append(alert)
                    if len(self._events) > 500:
                        self._events = self._events[-500:]
                if self._callback:
                    self._callback(alert)
                return alert

        except Exception as e:
            logger.debug("DNS parse error: %s", e)
        return None

    def get_events(self, n: int = 50) -> List[dict]:
        with self._lock:
            return list(reversed(self._events))[:n]

    def get_stats(self) -> dict:
        return {
            "total_dns_queries": self._total,
            "dns_attacks":       self._attacks,
            "tracked_ips":       len(self._query_times),
        }

    @staticmethod
    def _make_alert(src_ip, qname, ts, attack_type, reason, severity) -> dict:
        import time as _time
        logger.warning("🌐 DNS %s: %s → %s [%s]", attack_type, src_ip, qname, reason)
        return {
            "attack_type": attack_type,
            "label":       "DNS Attack",
            "src_ip":      src_ip,
            "query":       qname,
            "reason":      reason,
            "severity":    severity,
            "timestamp":   _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime(ts)),
        }
