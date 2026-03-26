"""
logger.py
---------
Unified logging module for the Professional IDS.

Provides two log streams:
    - Device events  →  logs/device_log.txt
    - Intrusion events → logs/intrusion_log.txt

All functions are thread-safe.
"""

import os
import logging
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR      = os.path.join(PROJECT_ROOT, "logs")

DEVICE_LOG_FILE    = os.path.join(LOG_DIR, "device_log.txt")
INTRUSION_LOG_FILE = os.path.join(LOG_DIR, "intrusion_log.txt")


def _make_logger(name, filepath):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    lgr = logging.getLogger(name)
    lgr.setLevel(logging.INFO)
    if not lgr.handlers:
        fh = logging.FileHandler(filepath, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(message)s"))
        lgr.addHandler(fh)
    return lgr


_dev_log = _make_logger("device_log", DEVICE_LOG_FILE)
_ids_log = _make_logger("intrusion_log", INTRUSION_LOG_FILE)


# ── Device Events ────────────────────────────────────────────

def log_device_event(ip, mac, vendor, event_type, device_type="Device"):
    """
    Log a device event (Connected / Disconnected / Reconnected).

    Example line:
        2026-03-09 10:45:22 | New Device | 192.168.1.25 | AA:BB:CC:DD:EE:FF | Xiaomi | Mobile
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _dev_log.info(f"{ts} | {event_type:<14} | {ip:<16} | {mac} | {vendor} | {device_type}")


# ── Intrusion Events ─────────────────────────────────────────

def log_intrusion_event(src_ip, dst_ip, protocol, attack_type,
                        risk_level, packet_size=0, attacker_name="Unknown", 
                        confidence=0.0, explanation=""):
    """
    Log an intrusion event with attacker device name, confidence and reason.

    Example line:
        2026-03-09 10:46:01 | Intrusion | Redmi-Note-11 | 192.168.1.45 → 10.0.0.1 | TCP | Flood | High | Conf: 0.92 | Reason: ...
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Format according to user preference
    _ids_log.info(
        f"{ts} | Intrusion | {attacker_name} | {src_ip} → {dst_ip} | {protocol} | "
        f"{attack_type} | {risk_level} | Conf: {confidence:.2f} | Reason: {explanation}"
    )


# ── Self-test ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Logger Test ===")
    log_device_event("192.168.1.25", "AA:BB:CC:DD:EE:FF", "Xiaomi", "New Device", "Mobile")
    log_device_event("192.168.1.32", "11:22:33:44:55:66", "Samsung", "Disconnected", "Mobile")
    log_intrusion_event("192.168.1.45", "10.0.0.1", "TCP", "Packet Flood", "High", 1500)
    print(f"  Device log   : {DEVICE_LOG_FILE}")
    print(f"  Intrusion log: {INTRUSION_LOG_FILE}")
    print("=== Done ===")
