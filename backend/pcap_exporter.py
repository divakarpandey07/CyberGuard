"""
pcap_exporter.py – Save suspicious flows as .pcap files
FREE: Uses Scapy (already in requirements.txt)
Suspicious flows are stored in memory and exported on demand.
"""
import os, time, logging, threading
from typing import List, Optional
from collections import deque

import config

logger = logging.getLogger("CyberGuard.PcapExporter")


class PcapExporter:
    """Buffers raw packets from flagged flows and writes .pcap on demand."""

    MAX_BUFFER = 5000  # max raw packets kept in memory

    def __init__(self):
        self._buffer : deque = deque(maxlen=self.MAX_BUFFER)
        self._lock   = threading.Lock()
        os.makedirs(config.PCAP_DIR, exist_ok=True)

    def add_packet(self, raw_pkt) -> None:
        """Add a raw Scapy packet (only attack flows should call this)."""
        with self._lock:
            self._buffer.append(raw_pkt)

    def export(self, filename: Optional[str] = None) -> str:
        """
        Write buffered packets to pcap file.
        Returns file path on success, empty string on failure.
        """
        if not filename:
            ts = time.strftime("%Y%m%d_%H%M%S")
            filename = f"cyberguard_capture_{ts}.pcap"

        path = os.path.join(config.PCAP_DIR, filename)

        with self._lock:
            pkts = list(self._buffer)

        if not pkts:
            logger.warning("PCAP export: buffer empty, nothing to write.")
            return ""

        try:
            from scapy.utils import wrpcap
            wrpcap(path, pkts)
            size_kb = os.path.getsize(path) / 1024
            logger.info("✅ PCAP exported: %s (%.1f KB, %d packets)", path, size_kb, len(pkts))
            return path
        except ImportError:
            logger.error("Scapy not installed – cannot export PCAP.")
            return ""
        except Exception as e:
            logger.error("PCAP export failed: %s", e)
            return ""

    def clear(self) -> int:
        """Clear buffer. Returns number of packets cleared."""
        with self._lock:
            n = len(self._buffer)
            self._buffer.clear()
        return n

    @property
    def buffer_size(self) -> int:
        with self._lock:
            return len(self._buffer)

    def list_exports(self) -> List[dict]:
        """List all exported pcap files."""
        try:
            files = []
            for f in os.listdir(config.PCAP_DIR):
                if f.endswith(".pcap"):
                    p    = os.path.join(config.PCAP_DIR, f)
                    stat = os.stat(p)
                    files.append({
                        "filename":  f,
                        "size_kb":   round(stat.st_size / 1024, 1),
                        "created":   time.strftime("%Y-%m-%d %H:%M:%S",
                                                   time.localtime(stat.st_ctime)),
                    })
            return sorted(files, key=lambda x: x["created"], reverse=True)
        except Exception:
            return []
