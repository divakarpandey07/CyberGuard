"""
geo_mapper.py – GeoIP lookup using ip-api.com
FREE: No API key needed. Limit: 45 requests/minute.
Cache: LRU cache for 500 IPs to minimise requests.
"""
import time, logging, threading
from collections import OrderedDict
from typing import Optional

import config

logger = logging.getLogger("CyberGuard.GeoMapper")

PRIVATE_PREFIXES = [
    ("10.",       "Private Network"),
    ("192.168.",  "Private Network"),
    ("172.16.",   "Private Network"),
    ("172.17.",   "Private Network"),
    ("172.18.",   "Private Network"),
    ("172.19.",   "Private Network"),
    ("172.20.",   "Private Network"),
    ("172.21.",   "Private Network"),
    ("172.22.",   "Private Network"),
    ("172.23.",   "Private Network"),
    ("172.24.",   "Private Network"),
    ("172.25.",   "Private Network"),
    ("172.26.",   "Private Network"),
    ("172.27.",   "Private Network"),
    ("172.28.",   "Private Network"),
    ("172.29.",   "Private Network"),
    ("172.30.",   "Private Network"),
    ("172.31.",   "Private Network"),
    ("127.",      "Loopback"),
    ("::1",       "Loopback"),
    ("fe80:",     "Link-Local"),
    ("0.",        "Unknown"),
]


class GeoMapper:
    """Thread-safe GeoIP lookup with in-memory LRU cache."""

    def __init__(self):
        self._cache      : OrderedDict = OrderedDict()
        self._lock       = threading.Lock()
        self._last_req   = 0.0
        self._rate_delay = 60.0 / 40  # 40 req/min safety margin
        self._total_hits = 0
        self._cache_hits = 0
        self._public_geo = None
        threading.Thread(target=self._fetch_public_geo, daemon=True, name="GeoMapperPublicGeo").start()

    def _fetch_public_geo(self):
        try:
            import requests
            resp = requests.get("http://ip-api.com/json/", timeout=5)
            d = resp.json()
            if d.get("status") == "success":
                self._public_geo = {
                    "ip":           "",
                    "country":      d.get("country",     "Local Network"),
                    "country_code": d.get("countryCode", "XX"),
                    "region":       d.get("regionName",  ""),
                    "city":         d.get("city",        ""),
                    "lat":          d.get("lat",          0.0),
                    "lon":          d.get("lon",          0.0),
                    "isp":          d.get("isp",         ""),
                    "org":          d.get("org",         ""),
                    "asn":          d.get("as",          ""),
                    "is_proxy":     d.get("proxy",       False),
                    "is_hosting":   d.get("hosting",     False),
                    "is_private":   True,
                    "flag":         f"https://flagcdn.com/16x12/{d.get('countryCode','xx').lower()}.png",
                }
                logger.info("Auto-detected public IP location: %s, %s (lat: %s, lon: %s)", 
                            d.get("city"), d.get("country"), d.get("lat"), d.get("lon"))
        except Exception as e:
            logger.debug("Failed to fetch public IP geo info: %s", e)

    def lookup(self, ip: str) -> dict:
        if not config.GEOIP_ENABLED or not ip or ip in ("?", ""):
            return self._unknown(ip)

        # Private / reserved IP check
        for prefix, label in PRIVATE_PREFIXES:
            if ip.startswith(prefix):
                if self._public_geo:
                    res = self._public_geo.copy()
                    res["ip"] = ip
                    res["org"] = f"Private Address ({label})"
                    return res
                return self._private(ip, label)

        # Cache check
        with self._lock:
            if ip in self._cache:
                self._cache.move_to_end(ip)
                self._cache_hits += 1
                return self._cache[ip]

        # Rate limiting
        elapsed = time.time() - self._last_req
        if elapsed < self._rate_delay:
            time.sleep(self._rate_delay - elapsed)

        result = self._fetch(ip)
        self._last_req   = time.time()
        self._total_hits += 1

        with self._lock:
            self._cache[ip] = result
            if len(self._cache) > config.GEOIP_CACHE_SIZE:
                self._cache.popitem(last=False)

        return result

    def lookup_many(self, ips: list) -> dict:
        """Batch lookup, returns {ip: geo_dict}."""
        return {ip: self.lookup(ip) for ip in set(ips) if ip}

    @property
    def stats(self) -> dict:
        return {
            "cached_ips":  len(self._cache),
            "total_lookups": self._total_hits,
            "cache_hits":  self._cache_hits,
        }

    # ── Internal ──────────────────────────────────────────────────────────

    @staticmethod
    def _fetch(ip: str) -> dict:
        try:
            import requests
            resp = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={
                    "fields": "status,country,countryCode,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"
                },
                timeout=5,
            )
            d = resp.json()
            if d.get("status") == "success":
                return {
                    "ip":           ip,
                    "country":      d.get("country",     "Unknown"),
                    "country_code": d.get("countryCode", "XX"),
                    "region":       d.get("regionName",  ""),
                    "city":         d.get("city",        ""),
                    "lat":          d.get("lat",          0.0),
                    "lon":          d.get("lon",          0.0),
                    "isp":          d.get("isp",         ""),
                    "org":          d.get("org",         ""),
                    "asn":          d.get("as",          ""),
                    "is_proxy":     d.get("proxy",       False),
                    "is_hosting":   d.get("hosting",     False),
                    "is_private":   False,
                    "flag":         f"https://flagcdn.com/16x12/{d.get('countryCode','xx').lower()}.png",
                }
        except Exception as e:
            logger.debug("GeoIP fetch error for %s: %s", ip, e)
        return GeoMapper._unknown(ip)

    @staticmethod
    def _private(ip: str, label: str) -> dict:
        return {
            "ip": ip, "country": label, "country_code": "XX",
            "region": "", "city": "", "lat": 0.0, "lon": 0.0,
            "isp": "Local Network", "org": "", "asn": "",
            "is_proxy": False, "is_hosting": False, "is_private": True,
            "flag": "",
        }

    @staticmethod
    def _unknown(ip: str) -> dict:
        return {
            "ip": ip or "?", "country": "Unknown", "country_code": "XX",
            "region": "", "city": "", "lat": 0.0, "lon": 0.0,
            "isp": "", "org": "", "asn": "",
            "is_proxy": False, "is_hosting": False, "is_private": False,
            "flag": "",
        }
