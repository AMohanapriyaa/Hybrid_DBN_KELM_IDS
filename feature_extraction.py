"""
feature_extraction.py
---------------------
Advanced network traffic feature extraction from live Scapy packets.

Extracts 15 numerical features per packet:

 #  Feature             Description
 ── ──────────────────── ──────────────────────────────────
  0  protocol            IP protocol number (6=TCP, 17=UDP…)
  1  packet_length       Total packet size in bytes
  2  src_port            Source transport port (0 if n/a)
  3  dst_port            Destination transport port (0 if n/a)
  4  tcp_flags           Numeric TCP flags (0 if not TCP)
  5  ttl                 IP Time-To-Live
  6  header_length       IP header length in bytes
  7  payload_size        Payload size (packet_length − header)
  8  packet_entropy      Shannon entropy of raw packet bytes
  9  time_delta          Seconds since previous packet
 10  packet_rate         1 / time_delta  (packets/sec, capped)
 11  flow_duration       Seconds since first packet in session
 12  connection_freq     # packets seen for this src→dst pair
 13  byte_count          Cumulative bytes for this src→dst pair
 14  packet_direction    0 = outbound (private→public), 1 = inbound
"""

import math
import struct
import socket
from collections import defaultdict

import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, Raw


# ── Public Constants ─────────────────────────────────────────
FEATURE_NAMES = [
    "protocol", "packet_length", "src_port", "dst_port",
    "tcp_flags", "ttl", "header_length", "payload_size",
    "packet_entropy", "time_delta", "packet_rate",
    "flow_duration", "connection_freq", "byte_count",
    "packet_direction",
]

NUM_FEATURES = len(FEATURE_NAMES)           # 15

ALL_DISPLAY_NAMES = [
    "src_ip", "dst_ip", "protocol", "packet_length",
    "src_port", "dst_port", "tcp_flags", "ttl",
    "timestamp",
]


# ── Helpers ──────────────────────────────────────────────────

def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence (bits)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def _is_private(ip_str: str) -> bool:
    """Check whether an IP is RFC-1918 private."""
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


def _tcp_flags_int(pkt) -> int:
    """Return numeric value of TCP flags (0 if not TCP)."""
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        return int(flags)
    return 0


# ── Stateful Feature Tracker ────────────────────────────────

class FeatureTracker:
    """
    Maintains per-flow state needed to compute advanced features
    (flow duration, connection frequency, byte counts, timing).

    Create one instance and pass every packet through `extract()`.
    """

    def __init__(self):
        self.prev_timestamp = None
        self.first_timestamp = None
        self.conn_freq = defaultdict(int)     # (src, dst) → count
        self.byte_count = defaultdict(int)    # (src, dst) → bytes

    def extract(self, packet):
        """
        Extract all 15 model features + metadata from one Scapy packet.

        Returns
        -------
        dict | None
            Feature dictionary, or None if the packet has no IP layer.
        """
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = int(ip.proto)
        pkt_len = len(packet)
        timestamp = float(packet.time)

        # ports
        src_port = 0
        dst_port = 0
        if packet.haslayer(TCP):
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)

        # TCP flags
        tcp_flags = _tcp_flags_int(packet)

        # TTL & header length
        ttl = int(ip.ttl)
        header_len = int(ip.ihl) * 4            # IHL is in 32-bit words

        # payload
        payload_bytes = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
        payload_size = len(payload_bytes)

        # entropy of whole packet
        pkt_entropy = _shannon_entropy(bytes(packet))

        # timing
        if self.first_timestamp is None:
            self.first_timestamp = timestamp

        time_delta = 0.0
        if self.prev_timestamp is not None:
            time_delta = max(timestamp - self.prev_timestamp, 0.0)
        self.prev_timestamp = timestamp

        packet_rate = min(1.0 / time_delta, 100_000.0) if time_delta > 0 else 0.0
        flow_duration = timestamp - self.first_timestamp

        # per-flow counters
        pair = (src_ip, dst_ip)
        self.conn_freq[pair] += 1
        self.byte_count[pair] += pkt_len

        # direction (0 = outbound private→public, 1 = inbound)
        direction = 0 if _is_private(src_ip) else 1

        return {
            # metadata (not fed to model, used for display / logging)
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "timestamp": timestamp,
            # model features (order must match FEATURE_NAMES)
            "protocol":         protocol,
            "packet_length":    pkt_len,
            "src_port":         src_port,
            "dst_port":         dst_port,
            "tcp_flags":        tcp_flags,
            "ttl":              ttl,
            "header_length":    header_len,
            "payload_size":     payload_size,
            "packet_entropy":   pkt_entropy,
            "time_delta":       time_delta,
            "packet_rate":      packet_rate,
            "flow_duration":    flow_duration,
            "connection_freq":  self.conn_freq[pair],
            "byte_count":       self.byte_count[pair],
            "packet_direction": direction,
        }


# ── Convenience Functions ────────────────────────────────────

def extract_model_features(feat_dict):
    """Return a 1-D numpy array of the 15 model features."""
    return np.array([feat_dict[n] for n in FEATURE_NAMES], dtype=np.float64)


def packets_to_dataframe(packets):
    """Convert a list of Scapy packets → pandas DataFrame of features."""
    tracker = FeatureTracker()
    records = []
    for pkt in packets:
        f = tracker.extract(pkt)
        if f is not None:
            records.append(f)
    if not records:
        return pd.DataFrame(columns=ALL_DISPLAY_NAMES + FEATURE_NAMES)
    return pd.DataFrame(records)


def get_model_feature_matrix(df):
    """Extract the (n_samples, 15) model-feature matrix from a DataFrame."""
    return df[FEATURE_NAMES].values.astype(np.float64)


# ── Self-test ────────────────────────────────────────────────
if __name__ == "__main__":
    from packet_capture import capture_n_packets

    print("=== Feature Extraction Test ===")
    pkts = capture_n_packets(10, timeout=15)
    df = packets_to_dataframe(pkts)
    print(df[FEATURE_NAMES].to_string(index=False))
    print(f"\nFeature matrix shape: {get_model_feature_matrix(df).shape}")
    print("=== Done ===")
