"""
sniffer.py – Live Packet Capture (Scapy)
v3: Added dns_callback and pcap_callback support, IPv6 support.
"""
import time, threading, logging, sys
from typing import Callable, Optional

import config

logger = logging.getLogger("CyberGuard.Sniffer")

try:
    from scapy.all import sniff, get_if_list
    from scapy.layers.inet  import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def has_sniffer_permission() -> bool:
    if not SCAPY_AVAILABLE:
        return False
    try:
        from scapy.all import sniff
        # Quick test to see if sniffing works with current permissions
        sniff(count=1, timeout=0.1, store=False)
        return True
    except Exception:
        return False


def check_requirements():
    if not SCAPY_AVAILABLE:
        print("\n❌ Scapy not installed.\n   Run: pip install scapy\n   Windows also needs Npcap: https://npcap.com/\n")
        sys.exit(1)
    if not has_sniffer_permission():
        print("\n❌ Insufficient permissions.\n   Linux/macOS: sudo python backend/app.py\n   Windows: Run as Administrator\n")
        sys.exit(1)


def _resolve_active_interface() -> tuple:
    if config.INTERFACE:
        try:
            from scapy.all import conf
            for iface in conf.ifaces.values():
                if iface.name == config.INTERFACE or iface.guid == config.INTERFACE:
                    return iface.name, getattr(iface, "ip", None)
        except Exception:
            pass
        return config.INTERFACE, None

    try:
        from scapy.all import conf
        active_ifaces = []
        for name, iface in conf.ifaces.items():
            ip = getattr(iface, "ip", "")
            if ip and ip not in ("127.0.0.1", "0.0.0.0", "::1"):
                if ip.startswith("169.254."):
                    continue
                active_ifaces.append(iface)
        
        if active_ifaces:
            def rank(iface):
                name = iface.name.lower()
                desc = getattr(iface, "description", "").lower()
                score = 0
                if "wi-fi" in name or "wi-fi" in desc or "wireless" in name or "wireless" in desc:
                    score += 20
                if "ethernet" in name or "ethernet" in desc or "lan" in name or "lan" in desc:
                    score += 10
                return score
            
            active_ifaces.sort(key=rank, reverse=True)
            chosen = active_ifaces[0]
            logger.info("Auto-detected active interface: %s (IP: %s)", chosen.name, chosen.ip)
            return chosen.name, chosen.ip
    except Exception as e:
        logger.warning("Error auto-detecting interface via conf.ifaces: %s", e)

    # Fallback to get_if_list
    try:
        ifaces = get_if_list()
        for iface in ifaces:
            low = iface.lower()
            if "lo" not in low and "loopback" not in low and "docker" not in low:
                return iface, None
        return (ifaces[0] if ifaces else None), None
    except Exception:
        return None, None


def _tcp_flags(tcp_layer) -> dict:
    f = int(tcp_layer.flags)
    return {
        "F": bool(f & 0x01), "S": bool(f & 0x02),
        "R": bool(f & 0x04), "P": bool(f & 0x08),
        "A": bool(f & 0x10), "U": bool(f & 0x20),
        "E": bool(f & 0x40), "C": bool(f & 0x80),
    }


class PacketSniffer:

    def __init__(self, callback: Callable[[dict], None],
                 dns_callback=None, pcap_callback=None):
        self._callback      = callback
        self._dns_callback  = dns_callback     # NEW v3
        self._pcap_callback = pcap_callback    # NEW v3
        self._running       = False
        self._thread        : Optional[threading.Thread] = None
        self._iface, self._ip = _resolve_active_interface()
        self._pkt_count     = 0
        self._err_count     = 0

    def start(self):
        if self._running:
            return
        check_requirements()
        self._running = True
        self._thread  = threading.Thread(
            target=self._capture_loop, daemon=True, name="PacketSniffer"
        )
        self._thread.start()
        logger.info("🔍 Live capture started | Interface: %s", self._iface or "default")

    def stop(self):
        self._running = False
        logger.info("Sniffer stopped | Packets: %d | Errors: %d",
                    self._pkt_count, self._err_count)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packet_count(self) -> int:
        return self._pkt_count

    def _capture_loop(self):
        try:
            sniff(
                iface=self._iface,
                filter=config.CAPTURE_FILTER,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            logger.error("❌ Permission denied. Run as root/Administrator.")
            self._running = False
        except Exception as e:
            logger.error("Sniffer fatal error: %s", e)
            self._running = False

    def _process_packet(self, raw_pkt) -> None:
        try:
            # IPv4 or IPv6
            if raw_pkt.haslayer(IP):
                ip = raw_pkt[IP]
                src_ip, dst_ip = ip.src, ip.dst
                proto = ip.proto
                ip_hdr_len = ip.ihl * 4
            elif raw_pkt.haslayer(IPv6):
                ip = raw_pkt[IPv6]
                src_ip, dst_ip = ip.src, ip.dst
                proto = ip.nh
                ip_hdr_len = 40  # fixed IPv6 header
            else:
                return

            # Skip loopback
            if src_ip.startswith("127.") or dst_ip.startswith("127."):
                return

            ts     = float(raw_pkt.time)
            length = len(raw_pkt)

            pkt_info = {
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": 0, "dst_port": 0,
                "protocol": proto, "length": length,
                "timestamp": ts, "tcp_flags": {},
                "header_length": ip_hdr_len, "window_size": -1,
                "_raw_packet": raw_pkt,
            }

            if raw_pkt.haslayer(TCP):
                tcp = raw_pkt[TCP]
                pkt_info["src_port"]     = tcp.sport
                pkt_info["dst_port"]     = tcp.dport
                pkt_info["tcp_flags"]    = _tcp_flags(tcp)
                pkt_info["window_size"]  = int(tcp.window)
                pkt_info["header_length"] = ip_hdr_len + (tcp.dataofs * 4 if tcp.dataofs else 20)
            elif raw_pkt.haslayer(UDP):
                udp = raw_pkt[UDP]
                pkt_info["src_port"]     = udp.sport
                pkt_info["dst_port"]     = udp.dport
                pkt_info["header_length"] = ip_hdr_len + 8
            elif raw_pkt.haslayer(ICMP):
                icmp = raw_pkt[ICMP]
                pkt_info["dst_port"]     = icmp.type
                pkt_info["header_length"] = ip_hdr_len + 8

            # Flow tracking callback
            self._callback(pkt_info)

            # DNS detection callback (v3)
            if self._dns_callback:
                self._dns_callback(raw_pkt)

            # PCAP export callback (v3) — only store attack-flagged later
            if self._pcap_callback:
                self._pcap_callback(raw_pkt)

            self._pkt_count += 1

        except Exception as e:
            self._err_count += 1
            if self._err_count % 200 == 0:
                logger.debug("Parse error #%d: %s", self._err_count, e)
