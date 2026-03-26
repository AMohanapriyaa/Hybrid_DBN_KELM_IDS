"""
intrusion_detection.py
----------------------
Professional IDS engine — Hybrid DBN-KELM with attack classification.

Pipeline:
    Device Discovery → Continuous Monitoring → Packet Capture
    → Feature Extraction → DBN Feature Learning
    → KELM Classification → Attack Classification
    → Explainable AI → Alert System → Logging → IP Tracking

Features:
    - Attack type classification (DoS, Port Scan, etc.)
    - Terminal dashboard with live stats
    - Suspicious device tracking with vendor info
    - Unified logging (device + intrusion)
"""

import sys
import os
import time
import socket
import threading
from datetime import datetime
from collections import defaultdict, Counter, deque

import numpy as np

# Ensure project root is on path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP
from src.packet_capture import capture_n_packets, start_capture
from src.feature_extraction import (
    FeatureTracker,
    extract_model_features,
    packets_to_dataframe,
    get_model_feature_matrix,
    FEATURE_NAMES,
    NUM_FEATURES,
)
from src.dbn_model import DBNFeatureLearner
from src.kelm_classifier import AnomalyKELM
from src.explain_ai import IntrusionExplainer
from src.alert_system import show_alert, show_network_status_alert, show_intrusion_popup
from src.device_scanner import DeviceScanner, DeviceMonitor
from src.logger import log_intrusion_event
from src.telegram_alert import send_telegram_alert



# ── Configuration ──────────────────────────────────────────────
BASELINE_PACKET_COUNT = 2000   # Increased for robust learning
BASELINE_TIMEOUT      = 300    # Allow more time for baseline capture
DBN_EPOCHS            = 50
DBN_BATCH_SIZE        = 16
KELM_GAMMA            = 0.1
KELM_REGULARIZATION   = 1.0
ANOMALY_THRESHOLD_PCT = 95
HYBRID_ALPHA          = 0.6
ALERT_COOLDOWN        = 5
STATS_INTERVAL        = 50
DASHBOARD_INTERVAL    = 100     # print dashboard every N packets
STATUS_REPORT_INTERVAL = 60    # network status popup every N seconds

# False Positive Reduction Thresholds
CONFIDENCE_THRESHOLD  = 0.70     # Alert if confidence >= 70%
SUSPICIOUS_THRESHOLD  = 10     # Min packets to trigger alert
SUSPICIOUS_WINDOW     = 5.0    # Time window in seconds

# ── Targeted Detection Thresholds ────────────────────────────
CONNECTION_ATTEMPT_THRESHOLD = 5    # N connection attempts to trigger
CONNECTION_ATTEMPT_WINDOW    = 5.0  # seconds
PORT_PROBE_THRESHOLD         = 10   # N unique ports to trigger port scan alert
PORT_PROBE_WINDOW            = 5.0  # seconds
PACKET_FLOOD_THRESHOLD       = 200  # packets per second
PACKET_FLOOD_WINDOW          = 1.0  # 1 second sliding window
NETWORK_SCAN_THRESHOLD       = 5    # N unique dest IPs to trigger
NETWORK_SCAN_WINDOW          = 5.0  # seconds
DEDUP_WINDOW                 = 10.0 # seconds — group same attacker+type

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR    = os.path.join(PROJECT_ROOT, "models")

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


# ──────────────────────────────────────────────────────────────
#  Local Network Helper
# ──────────────────────────────────────────────────────────────

def _is_local_network(ip_str):
    """
    Check if an IP is on a local/private network (RFC-1918).
    Returns True for 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    """
    if not ip_str:
        return False
    try:
        parts = ip_str.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        return False
    except (ValueError, IndexError):
        return False


# ──────────────────────────────────────────────────────────────
#  Attack Classifier
# ──────────────────────────────────────────────────────────────

def classify_attack(feat):
    """
    Classify the type of attack based on packet features.

    Parameters
    ----------
    feat : dict
        Feature dictionary from FeatureTracker.extract()

    Returns
    -------
    tuple (attack_type: str, risk_level: str)
    """
    protocol    = int(feat.get("protocol", 0))
    pkt_len     = int(feat.get("packet_length", 0))
    dst_port    = int(feat.get("dst_port", 0))
    src_port    = int(feat.get("src_port", 0))
    tcp_flags   = int(feat.get("tcp_flags", 0))
    pkt_rate    = feat.get("packet_rate", 0)
    time_delta  = feat.get("time_delta", 1)
    conn_freq   = feat.get("connection_freq", 0)
    dst_ip      = feat.get("dst_ip", "")

    # ── Packet Flood / DoS ───────────────────────────────────
    if pkt_rate > 200 or (0 < time_delta < 0.001):
        return "Packet Flood / DoS", "High"

    # ── Port Scanning ────────────────────────────────────────
    if tcp_flags == 0 and protocol == 6:
        return "Port Scanning (NULL Scan)", "High"

    if tcp_flags == 0x29:   # FIN+PSH+URG = XMAS
        return "Port Scanning (XMAS Scan)", "High"

    if tcp_flags == 0x02 and conn_freq > 5:  # SYN probing
        return "Port Probe", "High"

    if tcp_flags == 0x02 and conn_freq > 20:  # mass SYN scan
        return "Port Scanning (SYN Scan)", "High"

    # ── Suspicious Connection Attempt ────────────────────────
    if tcp_flags == 0x02 and conn_freq > 3:
        return "Suspicious Connection Attempt", "Medium"

    # ── Abnormal Packet Size ─────────────────────────────────
    if pkt_len > 1400:
        return "Abnormal Packet Size", "Medium"

    if pkt_len < 40 and protocol == 6:
        return "Abnormal Packet Size (Tiny TCP)", "Medium"

    # ── Unknown Protocol ─────────────────────────────────────
    if protocol not in (1, 6, 17):
        return "Unknown Protocol", "Medium"

    # ── Network Scanning ────────────────────────────────────
    # (Handled by rule-based _detect_network_scan, but also classifiable here)
    if conn_freq > 10 and protocol == 1:  # ICMP sweeps
        return "Network Scanning", "High"

    # ── Default ──────────────────────────────────────────────
    return "Suspicious Traffic", "Low"


# ──────────────────────────────────────────────────────────────
#  IDS Engine
# ──────────────────────────────────────────────────────────────

class IntrusionDetectionSystem:
    """
    Professional real-time hybrid DBN-KELM intrusion detection system.

    Phases:
        0 – Device discovery + continuous monitoring
        1 – Baseline collection (normal traffic)
        2 – Model training (DBN autoencoder + KELM)
        3 – Real-time monitoring with attack classification
    """

    def __init__(self):
        self.dbn = DBNFeatureLearner(input_dim=NUM_FEATURES)
        self.kelm = AnomalyKELM(
            gamma=KELM_GAMMA,
            regularization=KELM_REGULARIZATION,
            threshold_percentile=ANOMALY_THRESHOLD_PCT,
            hybrid_alpha=HYBRID_ALPHA,
        )
        self.explainer = IntrusionExplainer()
        self.tracker = FeatureTracker()
        self.device_scanner = DeviceScanner()
        self.device_monitor = DeviceMonitor(self.device_scanner)

        # Victim & Gateway IP (auto-detect)
        self.victim_ip  = self._get_victim_ip()
        self.gateway_ip = self.device_scanner.gateway_ip
        print(f"[*] Victim IP detected  : {self.victim_ip}")
        print(f"[*] Gateway IP detected : {self.gateway_ip}")

        # counters
        self.packet_count = 0
        self.intrusion_count = 0
        self.suspicious_ips = defaultdict(lambda: {
            "count": 0, "vendor": "Unknown", "last_attack": "—"
        })
        self.last_alert_time = {}
        self._start_time = None
        self.discovered_devices = []

        # Alert Rate Limiting
        self.last_intrusion_popup_time = 0
        self.intrusion_buffer = []  # list of dicts during cooldown

        # Threshold Tracking
        self.suspicious_history = defaultdict(lambda: deque(maxlen=50)) # [timestamp, ...]

        # ── Targeted Detection Trackers ──────────────────────
        # Connection Attempt Tracker: {src_ip: deque([timestamp, ...])}
        self.connection_attempts = defaultdict(lambda: deque(maxlen=100))
        # Port Probe Tracker: {src_ip: {"ports": set(), "timestamps": deque()}}
        self.port_probe_tracker = defaultdict(lambda: {"ports": set(), "timestamps": deque(maxlen=200)})
        # Packet Flood Tracker: {src_ip: deque([timestamp, ...])}
        self.packet_rate_tracker = defaultdict(lambda: deque(maxlen=500))
        # Network Scan Tracker: {src_ip: {"ips": set(), "timestamps": deque()}}
        self.network_scan_tracker = defaultdict(lambda: {"ips": set(), "timestamps": deque(maxlen=200)})
        # Alert cooldown per detection type per IP: {(src_ip, det_type): last_time}
        self.targeted_alert_cooldown = {}
        # Deduplication tracker: {(src_ip, attack_type): {"first": t, "count": n, "detail": str}}
        self.dedup_tracker = {}

    # ── Victim IP Detection ───────────────────────────────────
    @staticmethod
    def _get_victim_ip():
        """Auto-detect this machine's local IP address."""
        try:
            # Connect to a public DNS to determine local IP (doesn't send data)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

    # ── Device lookup helper ─────────────────────────────────
    def _lookup_device_info(self, ip):
        """Find device details from discovered devices list."""
        for d in self.discovered_devices:
            if d.get("ip") == ip:
                return {
                    "hostname": d.get("hostname", "Unknown"),
                    "ip": d.get("ip", ip),
                    "mac": d.get("mac", "Unknown"),
                    "vendor": d.get("vendor", "Unknown"),
                    "device_type": d.get("device_type", "Unknown Device"),
                }
        # Also check known_devices from scanner
        for mac, info in self.device_scanner.known_devices.items():
            if info.get("ip") == ip:
                return {
                    "hostname": info.get("hostname", "Unknown"),
                    "ip": ip,
                    "mac": mac,
                    "vendor": info.get("vendor", "Unknown"),
                    "device_type": info.get("device_type", "Unknown Device"),
                }
        return {"hostname": "External", "ip": ip, "mac": "?",
                "vendor": "Unknown", "device_type": "Unknown Device"}

    # ── Phase 0 ──────────────────────────────────────────────
    def discover_devices(self):
        print("\n" + "=" * 62)
        print("  PHASE 0: WiFi NETWORK DEVICE DISCOVERY")
        print("=" * 62)
        print(f"[*] Scanning subnet: {self.device_scanner.subnet}")
        print("[*] Discovering connected devices via ARP scan...\n")

        self.discovered_devices = self.device_scanner.discover()
        print("\n[✓] Device discovery complete!")

        # Start continuous monitoring (Thread 2)
        self.device_monitor.start()

        # Start network status reporter (Thread 3)
        self._status_running = True
        self._status_thread = threading.Thread(
            target=self._status_reporter_loop, daemon=True)
        self._status_thread.start()
        print(f"[*] Network status reporter started (every {STATUS_REPORT_INTERVAL}s)")

    # ── Thread 3: Network Status Reporter ────────────────────
    def _status_reporter_loop(self):
        """Show a network status popup every STATUS_REPORT_INTERVAL seconds."""
        while self._status_running:
            time.sleep(STATUS_REPORT_INTERVAL)
            devices = self.device_monitor.get_active_devices()
            if not devices:
                devices = self.discovered_devices
            scan_time = datetime.now().strftime("%I:%M:%S %p")
            show_network_status_alert(devices, scan_time=scan_time)
            print(f"  📡 Network status report sent ({len(devices)} devices) [{scan_time}]")

    def _is_safe_traffic(self, feat):
        """
        Check if traffic belongs to common background protocols or router traffic.
        Safe traffic is logged but never triggers an alert.
        """
        dst_ip   = feat.get("dst_ip", "")
        src_ip   = feat.get("src_ip", "")
        dst_port = int(feat.get("dst_port", 0))
        src_port = int(feat.get("src_port", 0))

        # 1. Multicast / Local Discovery
        if dst_ip.startswith("224.") or dst_ip.startswith("239."):
            return True

        # 2. Broadcast / DHCP / ARP
        if dst_ip == "255.255.255.255" or dst_ip.endswith(".255"):
            return True
        
        # 3. DNS Traffic (Port 53 is usually normal infrastructure)
        if dst_port == 53 or src_port == 53:
            return True

        # 4. mDNS / SSDP / DHCP
        if dst_port in (5353, 1900, 67, 68):
            return True

        # 5. ARP / Non-IP
        if not dst_ip:
            return True

        return False

    # ══════════════════════════════════════════════════════════
    #  TARGETED DETECTION METHODS (Victim-IP-Focused)
    # ══════════════════════════════════════════════════════════

    def _detect_connection_attempt(self, feat):
        """
        Detect repeated connection attempts targeting the victim device.

        Rule: Same source IP sends >= CONNECTION_ATTEMPT_THRESHOLD
              TCP SYN packets to the victim within CONNECTION_ATTEMPT_WINDOW seconds.

        Returns
        -------
        tuple (detected: bool, attack_type: str, risk_level: str) or (False, None, None)
        """
        dst_ip = feat.get("dst_ip", "")
        src_ip = feat.get("src_ip", "")
        protocol = int(feat.get("protocol", 0))
        tcp_flags = int(feat.get("tcp_flags", 0))

        # Only track TCP SYN packets targeting the victim
        if dst_ip != self.victim_ip or protocol != 6:
            return False, None, None

        # Track ALL TCP connection attempts (SYN flag set, bit 1)
        is_syn = (tcp_flags & 0x02) != 0
        if not is_syn:
            return False, None, None

        now = time.time()
        history = self.connection_attempts[src_ip]
        history.append(now)

        # Remove entries outside the time window
        while history and (now - history[0] > CONNECTION_ATTEMPT_WINDOW):
            history.popleft()

        count = len(history)
        if count >= CONNECTION_ATTEMPT_THRESHOLD:
            return True, "Suspicious Connection Attempt", "Medium"

        return False, None, None

    def _detect_port_probe(self, feat):
        """
        Detect port probing — same device scanning multiple ports on the victim.

        Rule: Same source IP targets > PORT_PROBE_THRESHOLD different
              destination ports on the victim within PORT_PROBE_WINDOW seconds.

        Returns
        -------
        tuple (detected: bool, attack_type: str, risk_level: str) or (False, None, None)
        """
        dst_ip = feat.get("dst_ip", "")
        src_ip = feat.get("src_ip", "")
        protocol = int(feat.get("protocol", 0))
        dst_port = int(feat.get("dst_port", 0))

        # Only track TCP/UDP packets targeting specific ports on the victim
        if dst_ip != self.victim_ip or protocol not in (6, 17) or dst_port == 0:
            return False, None, None

        now = time.time()
        tracker = self.port_probe_tracker[src_ip]
        tracker["timestamps"].append((now, dst_port))

        # Remove old entries and their ports outside the window
        while tracker["timestamps"] and (now - tracker["timestamps"][0][0] > PORT_PROBE_WINDOW):
            tracker["timestamps"].popleft()

        # Recompute unique ports from active window
        active_ports = set(port for _, port in tracker["timestamps"])
        tracker["ports"] = active_ports

        if len(active_ports) > PORT_PROBE_THRESHOLD:
            return True, "Port Probe", "High"

        return False, None, None

    def _detect_packet_flood(self, feat):
        """
        Detect packet floods — high-rate packet transmission to the victim.

        Rule: Same source IP sends > PACKET_FLOOD_THRESHOLD packets/second
              to the victim device.

        Returns
        -------
        tuple (detected: bool, attack_type: str, risk_level: str, rate: float) or (False, None, None, 0)
        """
        dst_ip = feat.get("dst_ip", "")
        src_ip = feat.get("src_ip", "")

        # Only track packets targeting the victim
        if dst_ip != self.victim_ip:
            return False, None, None, 0

        now = time.time()
        history = self.packet_rate_tracker[src_ip]
        history.append(now)

        # Remove entries outside the 1-second window
        while history and (now - history[0] > PACKET_FLOOD_WINDOW):
            history.popleft()

        rate = len(history) / PACKET_FLOOD_WINDOW  # packets per second

        if rate > PACKET_FLOOD_THRESHOLD:
            return True, "Packet Flood / DoS", "High", rate

        return False, None, None, 0

    def _detect_network_scan(self, feat):
        """
        Detect network scanning — a device probing multiple IPs on the network.

        Rule: Same source IP sends packets to > NETWORK_SCAN_THRESHOLD different
              destination IPs within NETWORK_SCAN_WINDOW seconds.

        Returns
        -------
        tuple (detected: bool, attack_type: str, risk_level: str) or (False, None, None)
        """
        src_ip = feat.get("src_ip", "")
        dst_ip = feat.get("dst_ip", "")

        # Skip if source is our machine or the gateway
        if src_ip in (self.victim_ip, self.gateway_ip):
            return False, None, None

        # Skip broadcast / multicast
        if dst_ip.startswith("224.") or dst_ip.startswith("239.") or dst_ip == "255.255.255.255" or dst_ip.endswith(".255"):
            return False, None, None

        now = time.time()
        tracker = self.network_scan_tracker[src_ip]
        tracker["timestamps"].append((now, dst_ip))

        # Remove old entries outside the window
        while tracker["timestamps"] and (now - tracker["timestamps"][0][0] > NETWORK_SCAN_WINDOW):
            tracker["timestamps"].popleft()

        # Recompute unique destination IPs from active window
        active_ips = set(ip for _, ip in tracker["timestamps"])
        tracker["ips"] = active_ips

        if len(active_ips) > NETWORK_SCAN_THRESHOLD:
            return True, "Network Scanning", "High"

        return False, None, None

    def _trigger_targeted_alert(self, feat, attack_type, risk_level, extra_info=""):
        """
        Generate alert, console output, logging, and popup for a targeted detection.
        Uses per-IP per-detection-type cooldown to avoid spam.
        """
        src = feat["src_ip"]
        dst = feat["dst_ip"]
        cooldown_key = (src, attack_type)
        now = time.time()

        # Update counters always
        self.intrusion_count += 1
        self.suspicious_ips[src]["count"] += 1
        self.suspicious_ips[src]["last_attack"] = attack_type

        # Device identification
        atk_info = self._lookup_device_info(src)
        tgt_info = self._lookup_device_info(dst)
        self.suspicious_ips[src]["vendor"] = atk_info.get("vendor", "Unknown")
        self.suspicious_ips[src]["hostname"] = atk_info.get("hostname", "Unknown Device")
        self.suspicious_ips[src]["device_type"] = atk_info.get("device_type", "Unknown")

        # ── EXTERNAL IP FILTER ───────────────────────────────
        # Only alert on local network devices, not internet servers
        if not _is_local_network(src):
            return

        # Build explanation
        explanation = f"{attack_type} detected from {src} → {dst}"
        if extra_info:
            explanation += f"; {extra_info}"

        # ── Console Alert (with device name) ─────────────────
        dev_name = atk_info.get("hostname", "Unknown Device")
        dev_vendor = atk_info.get("vendor", "Unknown")
        dev_type = atk_info.get("device_type", "Unknown Device")
        print(f"\n  \033[91m══════════════════════════════════════\033[0m")
        print(f"  \033[91m  INTRUSION DETECTED\033[0m")
        print(f"  \033[91m\033[0m")
        print(f"  \033[91m  Attack Type : {attack_type}\033[0m")
        print(f"  \033[91m  Attacker IP : {src}\033[0m")
        print(f"  \033[91m  Device Name : {dev_name}\033[0m")
        print(f"  \033[91m  Vendor      : {dev_vendor}\033[0m")
        print(f"  \033[91m  Device Type : {dev_type}\033[0m")
        print(f"  \033[91m  Target IP   : {dst}\033[0m")
        proto_name = PROTO_NAMES.get(int(feat.get('protocol', 0)), 'Other')
        print(f"  \033[91m  Protocol    : {proto_name}\033[0m")
        print(f"  \033[91m  Risk Level  : {risk_level}\033[0m")
        if extra_info:
            print(f"  \033[91m  Detail      : {extra_info}\033[0m")
        print(f"  \033[91m══════════════════════════════════════\033[0m\n")

        # ── Logging ──────────────────────────────────────────
        log_intrusion_event(
            src, dst, proto_name, attack_type, risk_level,
            feat.get("packet_length", 0),
            atk_info.get("hostname", "Unknown"),
            confidence=1.0,
            explanation=explanation
        )

        # ── Popup Alert (with cooldown) ──────────────────────
        last_popup = self.targeted_alert_cooldown.get(cooldown_key, 0)
        if now - last_popup < ALERT_COOLDOWN:
            return  # Skip popup to prevent spam

        self.targeted_alert_cooldown[cooldown_key] = now

        show_alert(
            src, dst, feat["protocol"],
            feat["packet_length"], feat["timestamp"],
            explanation,
            attack_type=attack_type,
            risk_level=risk_level,
            confidence=1.0,
            summary_count=self.suspicious_ips[src]["count"],
            top_ip=src,
            attacker_info=atk_info,
            target_info=tgt_info,
        )

        # ── TELEGRAM ALERT ───────────────────────────────────
        timestamp_str = datetime.fromtimestamp(feat.get("timestamp", time.time())).strftime("%Y-%m-%d %H:%M:%S")
        telegram_msg = (
            f"⚠️ INTRUSION DETECTED\n\n"
            f"Attack Type : {attack_type}\n"
            f"Attacker IP : {src}\n"
            f"Target IP : {dst}\n"
            f"Protocol : {proto_name}\n"
            f"Risk Level : {risk_level}\n"
            f"Time : {timestamp_str}"
        )
        # Run in a background thread to prevent pausing packet analysis
        threading.Thread(target=send_telegram_alert, args=(telegram_msg,), daemon=True).start()

        # ── DESKTOP POPUP ALERT (plyer) ───────────────────────
        popup_msg = (
            f"Attack Type: {attack_type}\n"
            f"Attacker IP: {src}\n"
            f"Target IP: {dst}"
        )
        # Run in background to avoid blocking
        threading.Thread(target=show_intrusion_popup, args=(popup_msg,), daemon=True).start()


        # ── DEDUPLICATION: Print summary when window expires ──
        dedup_key = (src, attack_type)
        now_d = time.time()
        if dedup_key in self.dedup_tracker:
            entry = self.dedup_tracker[dedup_key]
            if now_d - entry["first"] < DEDUP_WINDOW:
                entry["count"] += 1
                entry["detail"] = extra_info
                return  # suppressed, just increment
            else:
                # Window expired — print summary of grouped alerts
                if entry["count"] > 1:
                    print(f"\n  \033[93m── {attack_type.upper()} SUMMARY ───────────────────\033[0m")
                    print(f"  \033[93m  Attacker IP  : {src}\033[0m")
                    print(f"  \033[93m  Device Name  : {dev_name}\033[0m")
                    print(f"  \033[93m  Total Alerts : {entry['count']} (grouped)\033[0m")
                    print(f"  \033[93m  Time Window  : {DEDUP_WINDOW:.0f} seconds\033[0m")
                    if entry["detail"]:
                        print(f"  \033[93m  Last Detail  : {entry['detail']}\033[0m")
                    print(f"  \033[93m──────────────────────────────────────\033[0m\n")
                # Start new window
                self.dedup_tracker[dedup_key] = {"first": now_d, "count": 1, "detail": extra_info}
        else:
            self.dedup_tracker[dedup_key] = {"first": now_d, "count": 1, "detail": extra_info}

    def _heuristic_score(self, feat):
        """
        Calculate a score (0.0 - 1.0) based on rule-based suspicious indicators.
        """
        score = 0.0
        pkt_rate = feat.get("packet_rate", 0)
        conn_freq = feat.get("connection_freq", 0)
        pkt_len = int(feat.get("packet_length", 0))
        proto = int(feat.get("protocol", 0))

        # Indicators
        if pkt_rate > 300: score += 0.4
        elif pkt_rate > 100: score += 0.2

        if conn_freq > 15: score += 0.3

        if pkt_len > 1400: score += 0.2
        if pkt_len < 40 and proto == 6: score += 0.2 # Tiny TCP

        if proto not in (1, 6, 17): score += 0.3

        return min(score, 1.0)

    def _check_threshold(self, src_ip):
        """
        Check if an IP has exceeded the suspicious packet threshold within the time window.
        Returns (is_over_threshold, threshold_score)
        """
        now = time.time()
        history = self.suspicious_history[src_ip]
        history.append(now)

        # Remove old entries outside window
        while history and (now - history[0] > SUSPICIOUS_WINDOW):
            history.popleft()

        count = len(history)
        is_over = count >= SUSPICIOUS_THRESHOLD

        # Score based on how close/far we are from threshold
        threshold_score = min(count / SUSPICIOUS_THRESHOLD, 1.5) # Caps at 1.5 for extra weight
        return is_over, min(threshold_score, 1.0)

    def _compute_confidence(self, ai_score, heuristic_score, rate_score, threshold_score):
        """
        Weighted confidence score (0.0 - 1.0)
        """
        confidence = (
            (0.40 * ai_score) +
            (0.25 * heuristic_score) +
            (0.20 * rate_score) +
            (0.15 * threshold_score)
        )
        return min(confidence, 1.0)

    # ── Phase 1 ──────────────────────────────────────────────
    def collect_baseline(self):
        print("\n" + "=" * 62)
        print("  PHASE 1: COLLECTING BASELINE TRAFFIC")
        print("=" * 62)
        print(f"[*] Capturing {BASELINE_PACKET_COUNT} packets as baseline…")
        print("[*] Generate normal traffic (browse web, ping, etc.)\n")

        pkts = capture_n_packets(BASELINE_PACKET_COUNT, timeout=BASELINE_TIMEOUT)

        if len(pkts) < 10:
            print("[!] Very few packets captured – results may be unreliable.")

        df = packets_to_dataframe(pkts)
        if df.empty:
            print("[!] No valid IP packets. Exiting.")
            sys.exit(1)

        X = get_model_feature_matrix(df)
        print(f"[*] Feature matrix: {X.shape[0]} samples × {X.shape[1]} features")
        return X

    # ── Phase 2 ──────────────────────────────────────────────
    def train_models(self, X_baseline):
        print("\n" + "=" * 62)
        print("  PHASE 2: TRAINING MODELS")
        print("=" * 62)

        print("\n[1/4] Training Deep Belief Network autoencoder…")
        self.dbn.train(X_baseline, epochs=DBN_EPOCHS, batch_size=DBN_BATCH_SIZE)

        print("[2/4] Encoding baseline features…")
        X_enc = self.dbn.transform(X_baseline)
        print(f"[*] Encoded shape: {X_enc.shape}")

        print("[3/4] Computing baseline reconstruction errors…")
        recon_errs = self.dbn.reconstruction_error(X_baseline)
        print(f"[*] Mean recon error: {recon_errs.mean():.6f}")

        print("[4/4] Training KELM anomaly detector (hybrid)…")
        self.kelm.train(X_enc, recon_errors_normal=recon_errs)

        self.explainer.set_training_data(X_baseline)
        self.dbn.save(MODEL_DIR)
        self.is_trained = True
        print("\n[✓] All models trained & saved!")

    # ── prediction wrapper for LIME ──────────────────────────
    def _predict_fn(self, X):
        return self.kelm.predict_proba(self.dbn.transform(X))

    # ── Per-packet processing ────────────────────────────────
    def process_packet(self, pkt):
        """Main callback for Scapy sniffer."""
        if not self.is_trained:
            return

        try:
            if not pkt.haslayer(IP):
                return

            feat = self.tracker.extract(pkt)
            if not feat:
                return

            # STAGE 2: Traffic Filtering (Ignore background noise)
            if self._is_safe_traffic(feat):
                # We still count them in dashboard but ignore for intrusion
                self.packet_count += 1
                return

            self.packet_count += 1

            # ── TRAFFIC FILTERS (FALSE POSITIVE REDUCTION) ────
            src_ip = feat.get("src_ip", "")
            dst_ip = feat.get("dst_ip", "")

            # 1. Ignore packets from self or gateway
            if src_ip in (self.victim_ip, self.gateway_ip):
                return
            
            # 2. Ignore background/safe traffic
            if self._is_safe_traffic(feat):
                return

            # ── STAGE 2.5: TARGETED DETECTION (Rule-Based) ───
            # These run FIRST for packets targeting the victim device.
            # If any triggers, we alert immediately without needing AI.
            targeted_alert_fired = False

            if feat.get("dst_ip") == self.victim_ip:
                # 1. Packet Flood Detection (highest priority)
                flood_detected, flood_type, flood_risk, flood_rate = self._detect_packet_flood(feat)
                if flood_detected:
                    self._trigger_targeted_alert(
                        feat, flood_type, flood_risk,
                        extra_info=f"{flood_rate:.0f} pkt/s from {feat['src_ip']}"
                    )
                    targeted_alert_fired = True

                # 2. Port Probe Detection
                probe_detected, probe_type, probe_risk = self._detect_port_probe(feat)
                if probe_detected and not targeted_alert_fired:
                    ports = self.port_probe_tracker[feat['src_ip']]['ports']
                    self._trigger_targeted_alert(
                        feat, probe_type, probe_risk,
                        extra_info=f"{len(ports)} ports scanned"
                    )
                    targeted_alert_fired = True

                # 3. Connection Attempt Detection
                conn_detected, conn_type, conn_risk = self._detect_connection_attempt(feat)
                if conn_detected and not targeted_alert_fired:
                    count = len(self.connection_attempts[feat['src_ip']])
                    self._trigger_targeted_alert(
                        feat, conn_type, conn_risk,
                        extra_info=f"{count} attempts in {CONNECTION_ATTEMPT_WINDOW}s"
                    )
                    targeted_alert_fired = True

            # 4. Network Scanning Detection (runs for ALL traffic, not just victim)
            if not targeted_alert_fired:
                netscan_detected, netscan_type, netscan_risk = self._detect_network_scan(feat)
                if netscan_detected:
                    unique_ips = len(self.network_scan_tracker[feat['src_ip']]['ips'])
                    self._trigger_targeted_alert(
                        feat, netscan_type, netscan_risk,
                        extra_info=f"{unique_ips} IPs probed in {NETWORK_SCAN_WINDOW}s"
                    )
                    targeted_alert_fired = True

            # ── STAGE 3: AI Anomaly Detection ────────────────
            # Runs for ALL traffic (not just victim-targeted)
            model_f = extract_model_features(feat)
            X_enc = self.dbn.transform(model_f)
            recon_err = self.dbn.reconstruction_error(model_f)
            ai_prob = self.kelm.predict_proba(X_enc)[0]
            ai_score = ai_prob[1]
            prediction = self.kelm.hybrid_predict(X_enc, recon_err)[0]

            # STAGE 4: Multi-Stage Verification (skip if targeted already alerted)
            if not targeted_alert_fired and (prediction == 1 or ai_score > 0.7):
                self._handle_intrusion(feat, model_f, ai_score)

            # periodic status line (Called AFTER handling so counter is updated)
            if self.packet_count % STATS_INTERVAL == 0:
                self._print_stats(feat, prediction)

            # periodic dashboard
            if self.packet_count % DASHBOARD_INTERVAL == 0:
                self._print_dashboard()
        except Exception as e:
            # Prevent sniffer crash
            print(f"[!] Warning: Error processing packet: {e}")

    # ── Intrusion handling ───────────────────────────────────
    def _handle_intrusion(self, feat, model_f, ai_score):
        """
        Processes a suspected anomaly:
        1. Immediately increments the intrusion counter (Consistency Fix)
        2. Calculates confidence using AI + Heuristics + Threshold
        3. Logic: Trigger alert if (Is over threshold OR confidence >= 0.85)
        """
        src = feat["src_ip"]
        dst = feat["dst_ip"]
        
        # 1. COUNTER CONSISTENCY: Increment immediately (Requested)
        self.intrusion_count += 1
        
        # STAGE 4: Heuristic Verification
        h_score = self._heuristic_score(feat)

        # Packet rate score
        pkt_rate = feat.get("packet_rate", 0)
        p_rate_score = min(pkt_rate / 500.0, 1.0)

        # STAGE 5: Threshold Verification (10 packets in 5s)
        is_over_threshold, t_score = self._check_threshold(src)

        # STAGE 6: Confidence Scoring
        confidence = self._compute_confidence(ai_score, h_score, p_rate_score, t_score)

        # 2. ALERT TRIGGER CONDITION: OR logic (Threshold OR Confidence)
        if not (is_over_threshold or confidence >= CONFIDENCE_THRESHOLD):
            # Suspicious but doesn't meet full alert criteria (yet)
            # Log internally for dash but don't show popup
            self.suspicious_ips[src]["count"] += 1
            return

        # 3. INTRUSION CONFIRMED
        attack_type, risk_level = classify_attack(feat)

        # Device identification
        atk_info = self._lookup_device_info(src)
        tgt_info = self._lookup_device_info(dst)

        # ── EXTERNAL IP FILTER ───────────────────────────────
        # Only alert on local network devices, not internet servers
        if not _is_local_network(src):
            return

        # 4. DASHBOARD & LOGGING
        # Ensure dash stats reflect latest info
        self.suspicious_ips[src]["count"] += 1
        self.suspicious_ips[src]["last_attack"] = attack_type
        self.suspicious_ips[src]["vendor"] = atk_info.get("vendor", "Unknown")
        self.suspicious_ips[src]["hostname"] = atk_info.get("hostname", "Unknown Device")
        self.suspicious_ips[src]["device_type"] = atk_info.get("device_type", "Unknown")
        hits = self.suspicious_ips[src]["count"]

        # Detection Explanation Generation (with Fallback)
        reasons = []
        if ai_score > 0.8: reasons.append("AI model detects complex anomaly pattern")
        if h_score > 0.6: reasons.append("Rule-based heuristics indicate malicious activity")
        if pkt_rate > 300: reasons.append(f"High packet rate detected ({pkt_rate:.1f} pkt/s)")
        if t_score >= 1.0: reasons.append(f"Rapid connection attempts detected ({SUSPICIOUS_THRESHOLD}+ in {SUSPICIOUS_WINDOW}s)")
        if int(feat.get("protocol", 0)) not in (1, 6, 17): reasons.append("Unusual protocol usage")

        explanation_str = "; ".join(reasons) if reasons else "Anomalous traffic pattern detected."

        # High visibility console alert (with device name)
        dev_name = atk_info.get("hostname", "Unknown Device")
        dev_vendor = atk_info.get("vendor", "Unknown")
        dev_type = atk_info.get("device_type", "Unknown Device")
        print(f"\n  \033[91m══════════════════════════════════════\033[0m")
        print(f"  \033[91m  INTRUSION DETECTED\033[0m")
        print(f"  \033[91m\033[0m")
        print(f"  \033[91m  Attack Type : {attack_type}\033[0m")
        print(f"  \033[91m  Attacker IP : {src}\033[0m")
        print(f"  \033[91m  Device Name : {dev_name}\033[0m")
        print(f"  \033[91m  Vendor      : {dev_vendor}\033[0m")
        print(f"  \033[91m  Device Type : {dev_type}\033[0m")
        print(f"  \033[91m  Target IP   : {dst}\033[0m")
        print(f"  \033[91m  Protocol    : {feat.get('protocol', 'N/A')}\033[0m")
        print(f"  \033[91m  Risk Level  : {risk_level}\033[0m")
        print(f"  \033[91m  Confidence  : {confidence*100:.1f}%\033[0m")
        short_exp = explanation_str if len(explanation_str) < 50 else explanation_str[:47] + "..."
        print(f"  \033[91m  Explanation : {short_exp}\033[0m")
        print(f"  \033[91m══════════════════════════════════════\033[0m\n")

        # 5. LOGGING & EXPLAINABILITY
        proto = "TCP" if feat.get("protocol") == 6 else "UDP" if feat.get("protocol") == 17 else "ICMP" if feat.get("protocol") == 1 else "Other"
        pkt_len = feat.get("length", feat.get("packet_length", 0))

        # Explainable AI (LIME) for deep analysis
        self.explainer.console_explanation(model_f, feat)

        # Log to file with confidence and explanation
        log_intrusion_event(
            src, dst, proto, attack_type, risk_level,
            pkt_len, atk_info.get("hostname", "Unknown"),
            confidence, explanation_str
        )

        # 6. TRIGGER POPUP ALERT
        from src.alert_system import show_alert

        now = time.time()
        # Per-attacker 5-second cooldown
        last_popup = self.suspicious_ips[src].get("last_popup_time", 0)
        
        if now - last_popup < 5.0:
            # Skip popup to prevent spam, but stats are already updated
            return
            
        self.suspicious_ips[src]["last_popup_time"] = now

        # Use the generated explanations for the popup
        gui_explanation = explanation_str if len(explanation_str) < 150 else explanation_str[:147] + "..."

        show_alert(src, dst, feat["protocol"],
                   feat["packet_length"], feat["timestamp"],
                   gui_explanation,
                   attack_type=attack_type,
                   risk_level=risk_level,
                   confidence=confidence,
                   summary_count=0,
                   top_ip=None,
                   attacker_info=atk_info,
                   target_info=tgt_info,
                   top_device_name=None,
                   top_vendor=None,
                   last_attack_type=None,
                   last_risk_level=None)

        # ── TELEGRAM ALERT ───────────────────────────────────
        telegram_msg = (
            f"🚨 <b>INTRUSION DETECTED</b>\n\n"
            f"<b>Attack Type:</b> {attack_type}\n"
            f"<b>Attacker IP:</b> {src}\n"
            f"<b>Target IP:</b> {dst}\n"
            f"<b>Risk Level:</b> {risk_level}\n"
            f"<b>Confidence:</b> {confidence*100:.1f}%\n"
            f"<b>Device:</b> {atk_info.get('hostname', 'Unknown')} ({atk_info.get('vendor', 'Unknown')})\n\n"
            f"<b>Explanation:</b> {gui_explanation}"
        )
        threading.Thread(target=send_telegram_alert, args=(telegram_msg,), daemon=True).start()


    # ── Statistics line ──────────────────────────────────────
    def _print_stats(self, feat, pred):
        status = "INTRUSION" if pred == 1 else "Normal"
        elapsed = time.time() - self._start_time if self._start_time else 1
        pps = self.packet_count / max(elapsed, 1)
        print(
            f"  [#{self.packet_count:>6}] "
            f"{feat['src_ip']:>15} → {feat['dst_ip']:<15} | "
            f"Proto:{feat['protocol']:>3} | "
            f"Len:{feat['packet_length']:>5} | "
            f"{status:<9} | "
            f"Intrusions:{self.intrusion_count} | "
            f"{pps:.1f} pkt/s"
        )

    # ── Terminal Dashboard ───────────────────────────────────
    def _print_dashboard(self):
        elapsed = time.time() - self._start_time if self._start_time else 1
        pps = self.packet_count / max(elapsed, 1)
        
        # Dynamic device count from active monitor
        active_devices = self.device_monitor.get_active_devices() if hasattr(self, 'device_monitor') else []
        n_devices = len(active_devices) if active_devices else len(self.discovered_devices)

        # Find top attacker
        top_attacker_ip = "None"
        top_attacker_count = 0
        if self.suspicious_ips:
            top_entry = max(self.suspicious_ips.items(), key=lambda x: x[1]["count"])
            top_attacker_ip = top_entry[0]
            top_attacker_count = top_entry[1]["count"]

        print(f"\n  ╔══════════════════ LIVE DASHBOARD ══════════════════╗")
        print(f"  ║ Victim IP (This PC) : {self.victim_ip:<27} ║")
        print(f"  ║ Connected Devices   : {n_devices:<27} ║")
        print(f"  ║{'':─<52}║")
        print(f"  ║ Packets Analyzed    : {self.packet_count:<27} ║")
        print(f"  ║ Total Attacks       : {self.intrusion_count:<27} ║")
        print(f"  ║ Packet Rate         : {pps:<26.1f} ║")
        print(f"  ║{'':─<52}║")
        print(f"  ║ Top Attacker IP     : {top_attacker_ip:<27} ║")
        if top_attacker_count > 0:
            print(f"  ║ Attacks from Top IP : {top_attacker_count:<27} ║")

        if self.suspicious_ips:
            print(f"  ║{'':─<52}║")
            print(f"  ║ ⚠ Suspicious Device List:{'':26}║")
            top_ips = sorted(self.suspicious_ips.items(),
                             key=lambda x: x[1]["count"], reverse=True)[:8]
            for ip, info in top_ips:
                hostname = info.get('hostname', 'Unknown')[:15]
                vendor_short = info['vendor'][:10] if len(info['vendor']) > 10 else info['vendor']
                atk_short = info['last_attack'][:12] if len(info['last_attack']) > 12 else info['last_attack']
                label = f"{ip} │ {hostname} │ {vendor_short} │ {atk_short}"
                print(f"  ║   {label:<49} ║")

        print(f"  ╚════════════════════════════════════════════════════╝\n")

    # ── Phase 3 ──────────────────────────────────────────────
    def start_monitoring(self):
        print("\n" + "=" * 62)
        print("  PHASE 3: REAL-TIME MONITORING")
        print("=" * 62)
        print(f"[*] Victim IP (this machine)  : {self.victim_ip}")
        print(f"[*] Targeted detection active : Connection / Port Probe / Flood")
        print(f"[*] Monitoring live traffic for intrusions…")
        print(f"[*] Models dir : {MODEL_DIR}")
        print("[*] Press Ctrl+C to stop.\n")
        self._start_time = time.time()

        try:
            start_capture(callback=self.process_packet, packet_count=0)
        except KeyboardInterrupt:
            self.print_summary()

    # ── Graceful Shutdown Summary ─────────────────────────────
    def print_summary(self):
        elapsed = time.time() - self._start_time if self._start_time else 0

        # Get latest device list from monitor
        devices = self.device_monitor.get_active_devices()
        if not devices:
            devices = self.discovered_devices

        print("\n\n" + "═" * 62)
        print("  NETWORK SECURITY SUMMARY")
        print("═" * 62)
        print(f"  Program Runtime       : {elapsed:.1f}s")
        print(f"  Total Packets         : {self.packet_count}")
        print(f"  Total Intrusions      : {self.intrusion_count}")
        if self.packet_count > 0:
            print(f"  Intrusion Rate        : "
                  f"{(self.intrusion_count/self.packet_count)*100:.2f}%")
            print(f"  Avg Analysis Rate     : "
                  f"{self.packet_count/max(elapsed,1):.1f} pkt/s")

        # Device list
        print(f"\n  Total Devices Discovered: {len(devices)}")
        if devices:
            print("  " + "─" * 58)
            print(f"  {'IP Address':<18} {'MAC Address':<20} "
                  f"{'Vendor':<22} {'Type'}")
            print("  " + "─" * 58)
            for d in devices:
                vendor = d.get('vendor', 'Unknown')
                if len(vendor) > 20:
                    vendor = vendor[:20] + '…'
                print(f"  {d.get('ip','?'):<18} {d.get('mac','?'):<20} "
                      f"{vendor:<22} {d.get('device_type','?')}")
            print("  " + "─" * 58)

        # Most suspicious device
        if self.suspicious_ips:
            top_ip = max(self.suspicious_ips.items(),
                         key=lambda x: x[1]["count"])
            print(f"\n  Most Suspicious IP    : {top_ip[0]}")
            print(f"  Attacks from this IP  : {top_ip[1]['count']}")
            print(f"  Vendor                : {top_ip[1]['vendor']}")
            print(f"  Last Attack Type      : {top_ip[1]['last_attack']}")

            print("\n  ── All Suspicious Devices ──")
            for ip, info in sorted(self.suspicious_ips.items(),
                                   key=lambda x: x[1]["count"],
                                   reverse=True)[:15]:
                print(f"    {ip:<20} – {info['vendor']:<20} – "
                      f"{info['count']} attack(s) – {info['last_attack']}")

        print("═" * 62)

    # ── Run ──────────────────────────────────────────────────
    def run(self):
        print("\n╔" + "═" * 60 + "╗")
        print("║  Professional AI-Based WiFi Security System               ║")
        print("║  Hybrid DBN-KELM Real-Time Intrusion Detection            ║")
        print("╚" + "═" * 60 + "╝")

        self.is_trained = False
        self._status_running = False
        self._status_thread = None
        try:
            self.discover_devices()
            X = self.collect_baseline()
            self.train_models(X)
            self.start_monitoring()
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user.")
            self._status_running = False
            self.device_monitor.stop()
            self.print_summary()
        except PermissionError:
            print("\n[!] Permission denied – run as Administrator.")
            sys.exit(1)
        except Exception as e:
            print(f"\n[!] ERROR: {e}")
            print("[!] Ensure Npcap is installed: https://npcap.com")
            raise


if __name__ == "__main__":
    IntrusionDetectionSystem().run()
