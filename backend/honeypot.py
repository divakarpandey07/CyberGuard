"""
honeypot.py – TCP Honeypot (fake service ports)
FREE: Pure Python standard sockets, zero dependencies.
Opens fake FTP/SSH/Telnet/RDP/MySQL/MSSQL/HTTP ports.
Any IP that connects is immediately flagged as suspicious.
"""
import socket, threading, time, logging
from typing import Callable, List, Optional

import config

logger = logging.getLogger("CyberGuard.Honeypot")

# Fake service banners — realistic enough to fool scanners
BANNERS = {
    21:   b"220 ProFTPD 1.3.5e Server (Ubuntu) [::ffff:192.168.1.1]\r\n",
    22:   b"SSH-2.0-OpenSSH_7.4p1 Ubuntu-10+deb9u7\r\n",
    23:   b"\xff\xfd\x01\xff\xfd\x1f\r\nUbuntu 18.04 LTS\r\nlogin: ",
    3389: b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00",
    8080: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.29\r\nContent-Type: text/html\r\n\r\n<html><h1>Admin Panel</h1></html>",
    1433: b"\x04\x01\x00\x2b\x00\x00\x01\x00",
    3306: b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x32\x2d\x30ubuntu0.18.04.1\x00",
}

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    3389: "RDP", 8080: "HTTP-Alt", 1433: "MSSQL", 3306: "MySQL",
}


class _PortListener:
    """Single-port honeypot server."""

    def __init__(self, port: int, on_hit: Callable):
        self._port   = port
        self._on_hit = on_hit
        self._sock   : Optional[socket.socket] = None
        self._running = False

    def start(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self._port))
            self._sock.listen(10)
            self._sock.settimeout(1.0)
            self._running = True
            t = threading.Thread(target=self._accept_loop, daemon=True,
                                 name=f"Honeypot:{self._port}")
            t.start()
            return True
        except OSError as e:
            logger.warning("Honeypot port %d unavailable: %s", self._port, e)
            return False

    def stop(self):
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
                threading.Thread(target=self._handle, args=(conn, addr),
                                 daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle(self, conn: socket.socket, addr):
        src_ip, src_port = addr
        data = b""
        try:
            banner = BANNERS.get(self._port, b"Welcome\r\n")
            conn.sendall(banner)
            conn.settimeout(2.0)
            try:
                data = conn.recv(1024)
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

        service = PORT_NAMES.get(self._port, f"Port-{self._port}")
        logger.warning("🍯 HONEYPOT HIT: %s → %s (port %d)", src_ip, service, self._port)
        self._on_hit({
            "src_ip":    src_ip,
            "src_port":  src_port,
            "port":      self._port,
            "service":   service,
            "data":      data.decode("utf-8", errors="replace")[:300],
            "timestamp": time.time(),
        })


class HoneypotManager:
    """Manages all honeypot port listeners."""

    def __init__(self, callback: Callable):
        self._callback  = callback
        self._listeners : List[_PortListener] = []
        self._hits      : List[dict] = []
        self._lock      = threading.Lock()
        self._active_ports: List[int] = []

    def start(self) -> List[int]:
        if not config.HONEYPOT_ENABLED:
            return []
        for port in config.HONEYPOT_PORTS:
            srv = _PortListener(port, self._on_hit)
            if srv.start():
                self._listeners.append(srv)
                self._active_ports.append(port)
        logger.info("🍯 Honeypot active on ports: %s", self._active_ports)
        return self._active_ports

    def stop(self):
        for srv in self._listeners:
            srv.stop()
        logger.info("Honeypot stopped")

    def get_hits(self, n: int = 50) -> List[dict]:
        with self._lock:
            return list(reversed(self._hits))[:n]

    def get_stats(self) -> dict:
        with self._lock:
            by_port = {}
            by_ip   = {}
            for h in self._hits:
                p = h["port"]
                i = h["src_ip"]
                by_port[p] = by_port.get(p, 0) + 1
                by_ip[i]   = by_ip.get(i, 0) + 1
            top_ips = sorted(by_ip.items(), key=lambda x: -x[1])[:10]
        return {
            "total_hits":   len(self._hits),
            "active_ports": self._active_ports,
            "by_port":      {PORT_NAMES.get(p, str(p)): c for p, c in by_port.items()},
            "top_ips":      [{"ip": ip, "count": c} for ip, c in top_ips],
        }

    def _on_hit(self, event: dict):
        with self._lock:
            self._hits.append(event)
            if len(self._hits) > 1000:
                self._hits = self._hits[-1000:]
        self._callback(event)
