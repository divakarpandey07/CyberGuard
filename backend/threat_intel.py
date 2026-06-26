"""
threat_intel.py – Threat Intelligence via AbuseIPDB
FREE tier: 1000 IP checks/day (register free at abuseipdb.com)
No key required to run — just returns empty results if key not set.
Cache: 1-hour TTL to conserve daily quota.
"""
import time, logging, threading
from collections import OrderedDict

import config

logger = logging.getLogger("CyberGuard.ThreatIntel")

_PRIVATE = ["10.", "192.168.", "172.16.", "172.17.", "172.18.",
            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
            "172.29.", "172.30.", "172.31.", "127.", "::1", "0."]


class ThreatIntelChecker:
    """
    Check IPs against AbuseIPDB.
    Thread-safe with LRU cache (TTL=1 hour).
    """
    CACHE_TTL = 3600
    MAX_CACHE = 500

    def __init__(self):
        self._cache    : OrderedDict = OrderedDict()
        self._lock     = threading.Lock()
        self._api_used = 0   # daily usage counter

    def check(self, ip: str) -> dict:
        """Returns reputation dict for IP."""
        if not ip or ip in ("?", ""):
            return self._empty(ip)
        if any(ip.startswith(p) for p in _PRIVATE):
            return {
                "ip": ip, "abuse_score": 0, "is_known_bad": False,
                "total_reports": 0, "source": "private",
                "shodan": {
                    "ports": [22, 80, 443, 8080],
                    "os": "Linux 5.x (Simulated OSINT Target)",
                    "org": "CyberGuard Lab Network",
                    "hostnames": ["victim-node.local"],
                    "source": "simulated"
                }
            }

        # Cache lookup
        with self._lock:
            if ip in self._cache:
                entry = self._cache[ip]
                if time.time() - entry.get("_ts", 0) < self.CACHE_TTL:
                    self._cache.move_to_end(ip)
                    return entry

        result = self._query(ip)
        result["_ts"] = time.time()

        with self._lock:
            self._cache[ip] = result
            if len(self._cache) > self.MAX_CACHE:
                self._cache.popitem(last=False)

        return result

    def _query_shodan(self, ip: str) -> dict:
        # Check if private/local
        if any(ip.startswith(p) for p in _PRIVATE):
            # Return a cool mock profile for testing simulations!
            return {
                "ports": [22, 80, 443, 8080],
                "os": "Linux 5.x (Simulated OSINT Target)",
                "org": "CyberGuard Lab Network",
                "hostnames": ["victim-node.local"],
                "source": "simulated"
            }
        
        key = config.SHODAN_API_KEY
        if not key:
            return {
                "ports": [],
                "os": "Unknown OS (No Key)",
                "org": "Unknown Org (No Key)",
                "hostnames": [],
                "source": "no_api_key"
            }
        
        try:
            import requests
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={key}",
                timeout=5
            )
            if r.status_code == 200:
                d = r.json()
                return {
                    "ports": d.get("ports", []),
                    "os": d.get("os", "Unknown OS") or "Unknown OS",
                    "org": d.get("org", "Unknown Org") or "Unknown Org",
                    "hostnames": d.get("hostnames", []),
                    "source": "shodan"
                }
            elif r.status_code == 404:
                return {
                    "ports": [],
                    "os": "Unindexed Host",
                    "org": "Unknown Hosting",
                    "hostnames": [],
                    "source": "not_scanned"
                }
        except Exception as e:
            logger.debug("Shodan error for %s: %s", ip, e)
        
        return {
            "ports": [],
            "os": "Error Fetching",
            "org": "Error Fetching",
            "hostnames": [],
            "source": "error"
        }

    def _query(self, ip: str) -> dict:
        # Default AbuseIPDB payload
        result = {
            "ip":             ip,
            "abuse_score":    0,
            "is_known_bad":   False,
            "total_reports":  0,
            "country":        "XX",
            "isp":            "",
            "domain":         "",
            "source":         "default",
        }

        # 1. Query AbuseIPDB
        abuse_key = config.ABUSEIPDB_API_KEY
        if abuse_key:
            try:
                import requests
                r = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 30},
                    timeout=5,
                )
                self._api_used += 1
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    score = d.get("abuseConfidenceScore", 0)
                    result.update({
                        "abuse_score":    score,
                        "is_known_bad":   score > 50,
                        "total_reports":  d.get("totalReports", 0),
                        "country":        d.get("countryCode", "XX"),
                        "isp":            d.get("isp", ""),
                        "domain":         d.get("domain", ""),
                        "source":         "abuseipdb",
                    })
                elif r.status_code == 429:
                    logger.warning("AbuseIPDB daily limit reached (1000/day on free tier)")
                    result["source"] = "abuseipdb_rate_limited"
                elif r.status_code == 401:
                    logger.error("AbuseIPDB: Invalid API key")
                    result["source"] = "abuseipdb_invalid_key"
            except Exception as e:
                logger.debug("AbuseIPDB query failed: %s", e)
                result["source"] = "abuseipdb_error"

        # 2. Query Shodan OSINT
        result["shodan"] = self._query_shodan(ip)
        return result

    @staticmethod
    def _empty(ip: str, source: str = "unknown") -> dict:
        return {
            "ip": ip or "?", "abuse_score": 0, "is_known_bad": False,
            "total_reports": 0, "country": "XX", "isp": "",
            "domain": "", "source": source,
            "shodan": {
                "ports": [],
                "os": "Unknown OS",
                "org": "Unknown Org",
                "hostnames": [],
                "source": "empty"
            }
        }

    @property
    def api_calls_today(self) -> int:
        return self._api_used

    @property
    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)
