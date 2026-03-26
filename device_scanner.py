"""
device_scanner.py
-----------------
Professional WiFi Network Device Discovery & Continuous Monitoring.

Features:
    - ARP scanning with Scapy
    - Vendor lookup via mac-vendor-lookup
    - Hostname resolution via socket
    - Continuous background monitoring (10s interval)
    - Detect: new joins, disconnects, reconnects
    - All events logged to logs/device_log.txt

Pipeline position:
    WiFi Network → Device Discovery → Vendor Identification
    → Continuous Monitoring → Packet Capture → IDS

Requirements:
    - Npcap installed (Windows)
    - Run as Administrator
"""

import os
import json
import socket
import subprocess
import re
import threading
import time
from typing import Dict, List, Optional, Any, Set

from scapy.all import ARP, Ether, srp, conf  # pyre-ignore
from mac_vendor_lookup import MacLookup  # pyre-ignore
from src.alert_system import show_new_device_alert  # pyre-ignore
from src.logger import log_device_event  # pyre-ignore


# ── Paths ────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR     = os.path.join(PROJECT_ROOT, "data")
KNOWN_DEVICES_FILE = os.path.join(DATA_DIR, "known_devices.json")

MONITOR_INTERVAL = 10   # seconds between scans

# ── Colors ───────────────────────────────────────────────────
CLR_RED    = "\033[91m"
CLR_BLUE   = "\033[94m"
CLR_YELLOW = "\033[93m"
CLR_RESET  = "\033[0m"


# ──────────────────────────────────────────────────────────────
#  DeviceScanner
# ──────────────────────────────────────────────────────────────

class DeviceScanner:
    """
    Discovers devices on the local WiFi network using ARP scanning.

    For each device provides:
        IP, MAC, Vendor, Device Type, Hostname, First Seen, Status
    """

    def __init__(self, subnet: Optional[str] = None, timeout: int = 3):
        self.subnet = subnet or self._get_local_subnet()
        self.timeout = timeout
        self.known_devices: Dict[str, Any] = self.load_known_devices()
        self.discovered_devices: List[Dict[str, Any]] = []

        # Gateway detection
        self.gateway_ip = self._get_gateway_ip()
        print(f"[*] Gateway IP detected: {self.gateway_ip}")

        # Initialize MacLookup
        self.mac_lookup = MacLookup()
        try:
            print("[*] Updating MAC vendor database...")
            self.mac_lookup.update_vendors()
            print("[✓] Vendor database updated.")
        except Exception as e:
            print(f"[*] Using local vendor cache ({e})")

    # ── Subnet auto-detection ────────────────────────────────

    @staticmethod
    def _get_local_subnet():
        """Auto-detect subnet from Windows ipconfig or socket fallback."""
        try:
            output = subprocess.check_output(
                "ipconfig", encoding="utf-8", errors="ignore"
            )
            ipv4_pattern = re.compile(
                r"IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)"
            )
            for match in ipv4_pattern.finditer(output):
                ip = match.group(1)
                if ip.startswith("127."):
                    continue
                parts = ip.split(".")
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            pass

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            pass

        return "192.168.1.0/24"

    @staticmethod
    def _get_gateway_ip():
        """Detect the default gateway IP using 'route print' on Windows."""
        try:
            output = subprocess.check_output(
                ["route", "print"], encoding="utf-8", errors="ignore"
            )
            # Look for 0.0.0.0 (default route) gateway column
            match = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", output)
            if match:
                return match.group(1)
        except Exception:
            pass

        # Fallback: assume .1 of the subnet if possible
        return "Unknown"

    # ── ARP Scan ─────────────────────────────────────────────

    def scan_network(self) -> List[Dict[str, str]]:
        """Send ARP requests and return list of {ip, mac} dicts."""
        arp_request = ARP(pdst=self.subnet)
        broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet      = broadcast / arp_request

        old_verb = conf.verb
        conf.verb = 0

        try:
            answered, _ = srp(packet, timeout=self.timeout, verbose=False)
        except PermissionError:
            print("[!] ERROR: Permission denied. Run as Administrator.")
            conf.verb = old_verb
            return []
        except Exception as e:
            print(f"[!] ERROR during ARP scan: {e}")
            conf.verb = old_verb
            return []
        finally:
            conf.verb = old_verb

        devices = []
        for sent, received in answered:
            devices.append({
                "ip":  received.psrc,
                "mac": received.hwsrc.upper(),
            })

        devices.sort(key=lambda d: tuple(int(p) for p in d["ip"].split(".")))
        return devices

    # ── Vendor lookup ────────────────────────────────────────

    def get_vendor(self, mac: str) -> str:
        """Look up vendor using mac-vendor-lookup library."""
        try:
            return self.mac_lookup.lookup(mac)
        except Exception:
            return "Unknown Vendor"

    # ── Hostname lookup ──────────────────────────────────────

    @staticmethod
    def get_hostname(ip: str) -> str:
        """Resolve hostname from IP via reverse DNS."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return "Unknown"

    # ── Device type heuristics ───────────────────────────────

    def get_device_type(self, vendor: str, hostname: str = "", ip: str = "") -> str:
        """
        Determine device type using multiple information sources:
        1. Gateway IP detection
        2. Hostname patterns (DESKTOP, ANDROID, etc.)
        3. Vendor name mappings
        """
        v = vendor.lower()
        h = hostname.lower()

        # 1. Router / Gateway Detection
        if ip == self.gateway_ip and self.gateway_ip != "Unknown":
            return "Router / Gateway"
        
        if any(k in v for k in ["tp-link", "d-link", "netgear", "linksys",
                                 "asus", "cisco", "ubiquiti", "mikrotik",
                                 "checkpoint", "fortinet", "huawei technologies"]):
            if any(k in h for k in ["router", "gateway", "ap", "wifi"]):
                return "Router / Gateway"
            # If IP is .1 or .254 it's highly likely a gateway
            if ip.endswith(".1") or ip.endswith(".254"):
                return "Router / Gateway"

        # 2. Hostname-Based Detection (Prioritize hostname for accuracy)
        if any(k in h for k in ["desktop", "laptop", "pc", "workstation", "surface"]):
            return "Laptop / PC"
        
        if any(k in h for k in ["android", "iphone", "redmi", "xiaomi", "galaxy", "pixel", "phone"]):
            return "Mobile Phone"

        if "ipad" in h or "tablet" in h:
            return "Tablet"

        # 3. Vendor-Based Detection (Fall back to vendor)
        # Mobile
        if any(k in v for k in ["samsung", "xiaomi", "redmi", "oppo",
                                 "vivo", "oneplus", "huawei", "realme",
                                 "motorola", "nokia", "lg electronics"]):
            return "Mobile Phone"

        # Apple specific logic
        if "apple" in v:
            if any(k in h for k in ["iphone", "ipad", "watch", "tv"]):
                if "iphone" in h: return "Mobile Phone"
                if "ipad" in h: return "Tablet"
                if "watch" in h: return "Smart Watch"
                if "tv" in h: return "Apple TV"
            # Generic apple fallback
            return "Mobile Phone / Mac"

        # PC / Laptop
        if any(k in v for k in ["intel", "dell", "hp", "lenovo",
                                 "acer", "msi", "gigabyte", "asustek"]):
            return "Laptop / PC"

        # Microsoft
        if "microsoft" in v:
            if "xbox" in h: return "Gaming Console"
            return "Laptop / PC"

        # Smart TV / Entertainment
        if any(k in v for k in ["sony", "lg display", "tcl", "hisense", "philips", "vizio"]):
            return "Smart TV"
        
        if any(k in v for k in ["nintendo", "playstation", "nvidia"]):
            return "Gaming Console"

        # Smart Home / IoT
        if any(k in v for k in ["amazon", "echo", "nest", "google", "roku", "sonos"]):
            if "speaker" in h or "echo" in h: return "Smart Speaker"
            return "Smart Device / IoT"

        if any(k in v for k in ["espressif", "raspberry", "arduino", "tuya", "sonoff"]):
            return "IoT Device"

        # Adapters (often generic but we can try)
        if any(k in v for k in ["realtek", "qualcomm", "broadcom", "mediatek"]):
            return "Laptop / PC (Network Adapter)"

        return "Unknown Device"

    # ── Known device persistence ─────────────────────────────

    @staticmethod
    def load_known_devices() -> Dict[str, Any]:
        """Load known devices from JSON and ensure it's a dictionary indexed by MAC."""
        if not os.path.exists(KNOWN_DEVICES_FILE):
            return {}
        try:
            with open(KNOWN_DEVICES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Convert list to dict if necessary (Legacy support)
            if isinstance(data, list):
                print("[*] Converting legacy known_devices list to dictionary format...")
                new_dict = {}
                for item in data:
                    if isinstance(item, dict) and "mac" in item:
                        mac = item.pop("mac").upper()
                        new_dict[mac] = item
                return new_dict
            
            # Ensure it's a dict and keys are upper case
            if isinstance(data, dict):
                return {k.upper(): v for k, v in data.items()}
            
            return {}
        except (json.JSONDecodeError, IOError, Exception) as e:
            print(f"[!] Warning: Could not load known devices: {e}")
            return {}

    @staticmethod
    def save_known_devices(devices):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(KNOWN_DEVICES_FILE, "w", encoding="utf-8") as f:
            json.dump(devices, f, indent=2, ensure_ascii=False)

    # ── Main discovery routine ───────────────────────────────

    def discover(self) -> List[Dict[str, Any]]:
        """
        Full device discovery workflow.
        Returns list of device dicts with all fields.
        """
        from src.alert_system import show_new_device_alert
        from src.logger import log_device_event
        from datetime import datetime

        raw_devices = self.scan_network()

        if not raw_devices:
            print("[!] No devices found. Check network / permissions.")
            self.discovered_devices = []
            return []

        now_str: str = datetime.now().strftime("%I:%M %p")
        new_device_count: int = 0
        results: List[Dict[str, Any]] = []

        for dev in raw_devices:
            mac: str = dev["mac"]
            ip: str  = dev["ip"]
            vendor   = self.get_vendor(mac)
            hostname = self.get_hostname(ip)
            dtype    = self.get_device_type(vendor, hostname, ip)

            if mac in self.known_devices:
                status = "Known Device"
                self.known_devices[mac]["ip"] = ip
                first_seen = self.known_devices[mac].get("first_seen", now_str)
            else:
                status = "⚠ New Device"
                new_device_count += 1  # pyre-ignore
                first_seen = now_str
                self.known_devices[mac] = {
                    "ip": ip,
                    "vendor": vendor,
                    "hostname": hostname,
                    "device_type": dtype,
                    "first_seen": first_seen,
                }

                # Console output matching user's requested format
                print(f"\n  {CLR_RED}╔══════════ NEW DEVICE CONNECTED ══════════╗{CLR_RESET}")
                print(f"  {CLR_RED}║  Device Name : {hostname:<27} ║{CLR_RESET}")
                print(f"  {CLR_RED}║  Vendor      : {vendor:<27} ║{CLR_RESET}")
                print(f"  {CLR_RED}║  IP Address  : {ip:<27} ║{CLR_RESET}")
                print(f"  {CLR_RED}║  MAC Address : {mac:<27} ║{CLR_RESET}")
                print(f"  {CLR_RED}║  Device Type : {dtype:<27} ║{CLR_RESET}")
                print(f"  {CLR_RED}║  First Seen  : {first_seen:<27} ║{CLR_RESET}")
                print(f"  {CLR_RED}╚════════════════════════════════════════════╝{CLR_RESET}")
                print(f"  {CLR_RED}[ALERT] NEW DEVICE DETECTED: {ip} ({hostname or vendor}){CLR_RESET}")

                # Log event
                log_device_event(ip, mac, vendor, "New Device", dtype)

                # Alert popup
                show_new_device_alert(
                    ip, mac, vendor=vendor,
                    hostname=hostname, device_type=dtype,
                    first_seen=first_seen,
                )

            results.append({
                "ip":          ip,
                "mac":         mac,
                "vendor":      vendor,
                "hostname":    hostname,
                "device_type": dtype,
                "first_seen":  first_seen,
                "status":      status,
            })

        # Save known devices
        self.save_known_devices(self.known_devices)

        # Print device table
        self._print_device_table(results)

        # Summary
        print(f"\n[*] Total devices found    : {len(results)}")
        print(f"[*] Known devices          : {len(results) - new_device_count}")  # pyre-ignore
        print(f"[*] New devices detected   : {new_device_count}")
        print(f"[*] Known devices file     : {KNOWN_DEVICES_FILE}")

        self.discovered_devices = results
        return results

    # ── Pretty table output ──────────────────────────────────

    @staticmethod
    def _print_device_table(devices):
        """Print a formatted table of discovered devices."""
        print("\n  Connected Devices:")
        print("  " + "═" * 90)
        print(f"  {'IP Address':<18} │ {'MAC Address':<20} │ {'Vendor':<22} │ "
              f"{'Device Type'}")
        print("  " + "─" * 90)
        for d in devices:
            vendor_short = d['vendor'][:20] if len(d['vendor']) > 20 else d['vendor']
            print(
                f"  {d['ip']:<18} │ {d['mac']:<20} │ {vendor_short:<22} │ "
                f"{d['device_type']}"
            )
        print("  " + "═" * 90)


# ──────────────────────────────────────────────────────────────
#  DeviceMonitor — Continuous Background Monitoring
# ──────────────────────────────────────────────────────────────

class DeviceMonitor:
    """
    Background thread that scans the network every MONITOR_INTERVAL
    seconds and detects device joins, disconnects, and reconnects.
    Also notifies when the device count changes.
    """

    def __init__(self, scanner: DeviceScanner):
        self.scanner = scanner
        self._active_macs: Set[str] = set()     # MACs currently online
        self._active_devices: List[Dict[str, Any]] = []     # Full device dicts for status popup
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._prev_count: int = 0
        self.last_alert_time: Dict[str, float] = {}    # key: MAC, value: timestamp

    def start(self):
        """Start the background monitoring thread."""
        if self._running:
            return
        self._running = True
        # Initialize active set from last scan
        for d in self.scanner.discovered_devices:
            self._active_macs.add(d["mac"])
        self._active_devices = list(self.scanner.discovered_devices)
        self._prev_count = len(self._active_macs)

        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        if self._thread:
            self._thread.start()
        print(f"[*] Device monitor started (scanning every {MONITOR_INTERVAL}s)")

    def stop(self):
        self._running = False

    def get_active_devices(self):
        """Return the latest list of active device dicts (thread-safe copy)."""
        return list(self._active_devices)

    def _monitor_loop(self):
        from datetime import datetime

        while self._running:
            time.sleep(MONITOR_INTERVAL)

            try:
                current_devices = self.scanner.scan_network()
            except Exception:
                continue

            current_macs: Set[str] = set()
            updated_devices: List[Dict[str, Any]] = []

            for dev in current_devices:
                mac: str = dev["mac"]
                ip: str = dev["ip"]
                current_macs.add(mac)

                vendor   = self.scanner.get_vendor(mac)
                hostname = self.scanner.get_hostname(ip)
                dtype    = self.scanner.get_device_type(vendor, hostname, ip)
                now_str  = datetime.now().strftime("%I:%M %p")

                updated_devices.append({
                    "ip": ip, "mac": mac, "vendor": vendor,
                    "hostname": hostname, "device_type": dtype,
                })

                if mac not in self._active_macs:
                    # Device joined (new or reconnected)
                    if mac in self.scanner.known_devices:
                        event = "Reconnected"
                        self.scanner.known_devices[mac]["ip"] = ip
                        # Blue message for known device
                        print(f"  {CLR_BLUE}📡 Device Reconnected: {ip} ({vendor} {dtype}){CLR_RESET}")
                        print(f"  {CLR_BLUE}[ALERT] Device reconnected: {ip} ({hostname or vendor}){CLR_RESET}")

                        # Trigger Alert Popup for Reconnection (with 45s suppression)
                        current_time = time.time()
                        if current_time - self.last_alert_time.get(mac, 0) > 45:
                            show_new_device_alert(
                                ip, mac, vendor=vendor,
                                hostname=hostname, device_type=dtype,
                                first_seen=now_str,
                                is_reconnect=True
                            )
                            self.last_alert_time[mac] = current_time
                    else:
                        event = "New Device"
                        self.scanner.known_devices[mac] = {
                            "ip": ip, "vendor": vendor,
                            "hostname": hostname,
                            "device_type": dtype,
                            "first_seen": now_str,
                        }
                        # Red alert block for brand-new device
                        print(f"\n  {CLR_RED}╔══════════ NEW DEVICE CONNECTED TO NETWORK ══════════╗{CLR_RESET}")
                        print(f"  {CLR_RED}║  IP Address  : {ip:<37} ║{CLR_RESET}")
                        print(f"  {CLR_RED}║  MAC Address : {mac:<37} ║{CLR_RESET}")
                        print(f"  {CLR_RED}║  Vendor      : {vendor:<37} ║{CLR_RESET}")
                        print(f"  {CLR_RED}║  Device Type : {dtype:<37} ║{CLR_RESET}")
                        print(f"  {CLR_RED}╚══════════════════════════════════════════════════════╝{CLR_RESET}")
                        print(f"  {CLR_RED}[ALERT] NEW DEVICE DETECTED: {ip} ({hostname or vendor}){CLR_RESET}")

                        # Trigger Alert Popup for New Device (with 45s suppression)
                        current_time = time.time()
                        if current_time - self.last_alert_time.get(mac, 0) > 45:
                            show_new_device_alert(
                                ip, mac, vendor=vendor,
                                hostname=hostname, device_type=dtype,
                                first_seen=now_str,
                            )
                            self.last_alert_time[mac] = current_time

                    log_device_event(ip, mac, vendor, event, dtype)
                    self.scanner.save_known_devices(self.scanner.known_devices)

            # Detect disconnects
            disconnected = self._active_macs - current_macs
            for mac in disconnected:
                info = self.scanner.known_devices.get(mac, {})
                ip   = info.get("ip", "?")
                # Yellow message for disconnection
                print(f"  {CLR_YELLOW}📴 Device Disconnected: {ip} ({mac}){CLR_RESET}")
                log_device_event(
                    ip, mac,
                    info.get("vendor", "Unknown"),
                    "Disconnected",
                    info.get("device_type", "Unknown Device"),
                )

            # Device count change notification
            current_count = len(current_macs)
            if current_count != self._prev_count:
                print(f"\n  ╔═══ Device Count Changed ═══╗")
                print(f"  ║  Previous : {self._prev_count:<16} ║")
                print(f"  ║  Current  : {current_count:<16} ║")
                print(f"  ╚═════════════════════════════╝\n")

            self._prev_count = current_count
            self._active_macs = current_macs
            self._active_devices = updated_devices


# ── Self-test ────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    # Ensure project root is on path for relative imports
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    print("=" * 62)
    print("  WiFi Network Device Discovery – Standalone Test")
    print("=" * 62)

    scanner = DeviceScanner()
    print(f"[*] Detected subnet: {scanner.subnet}")
    devices = scanner.discover()

    if devices:
        print("\n  Connected Devices:")
        for d in devices:
            print(f"    {d['ip']} → {d['vendor']} ({d['device_type']})")
    else:
        print("\n  No devices discovered.")

    print("\n" + "=" * 62)
    print("  Done.")
    print("=" * 62)
