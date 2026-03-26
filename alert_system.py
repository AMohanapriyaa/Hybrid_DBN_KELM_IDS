"""
alert_system.py
---------------
Thread-safe Tkinter alert system for the Professional IDS.

Supports three alert types via clean dispatch:
    1. Intrusion alerts       (RED)    — attacker/target device, summary, explanation
    2. New device alerts      (YELLOW) — hostname + vendor + device type
    3. Network status alerts  (BLUE)   — all connected devices summary
"""

import threading
import queue
import tkinter as tk
from tkinter import font as tkfont
from datetime import datetime


PROTOCOL_MAP = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
    47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF",
}


def get_protocol_name(p):
    return PROTOCOL_MAP.get(int(p), f"Other ({int(p)})")


RISK_COLORS = {
    "High":   "#e74c3c",
    "Medium": "#e67e22",
    "Low":    "#f1c40f",
}


# ── Singleton AlertManager ───────────────────────────────────

class AlertManager:
    """One Tk root on a dedicated thread; alerts are enqueued."""

    def __init__(self):
        self._q = queue.Queue()
        self._started = False
        self._lock = threading.Lock()
        self._current_intrusion_w = None

    def _ensure_started(self):
        with self._lock:
            if self._started:
                return
            self._started = True
            threading.Thread(target=self._tk_loop, daemon=True).start()

    def _tk_loop(self):
        self._root = tk.Tk()
        self._root.withdraw()
        self._root.after(200, self._poll)
        self._root.mainloop()

    def _poll(self):
        while not self._q.empty():
            try:
                d = self._q.get_nowait()
                alert_type = d.get("_type", "intrusion")
                if alert_type == "new_device":
                    self._build_device_window(d)
                elif alert_type == "network_status":
                    self._build_status_window(d)
                else:
                    self._build_intrusion_window(d)
            except queue.Empty:
                break
        try:
            self._root.after(200, self._poll)
        except tk.TclError:
            pass

    # ══════════════════════════════════════════════════════════
    #  Helper: device detail rows
    # ══════════════════════════════════════════════════════════

    def _add_device_section(self, parent, title, info, hf, bf, bg):
        """Add a labeled device info section to a parent frame."""
        tk.Label(parent, text=title, font=hf, fg="#e67e22",
                 bg=bg, anchor="w").pack(fill=tk.X, pady=(5, 2))
        for lbl, val in [("Device Name", info.get("hostname", "Unknown")),
                         ("IP Address", info.get("ip", "?")),
                         ("MAC Address", info.get("mac", "?")),
                         ("Vendor", info.get("vendor", "Unknown")),
                         ("Device Type", info.get("device_type", "Device"))]:
            r = tk.Frame(parent, bg=bg)
            r.pack(fill=tk.X, pady=1)
            tk.Label(r, text=f"  {lbl}:", font=hf, fg="#8be9fd",
                     bg=bg, width=14, anchor="w").pack(side=tk.LEFT)
            tk.Label(r, text=str(val), font=bf, fg="#f8f8f2",
                     bg=bg, anchor="w").pack(side=tk.LEFT,
                                              fill=tk.X, expand=True)

    # ══════════════════════════════════════════════════════════
    #  1. INTRUSION ALERT  (RED)
    # ══════════════════════════════════════════════════════════

    def _build_intrusion_window(self, d):
        # Prevent stacking: close previous window
        if self._current_intrusion_w:
            try:
                if self._current_intrusion_w.winfo_exists():
                    self._current_intrusion_w.destroy()
            except tk.TclError:
                pass

        w = tk.Toplevel(self._root)
        self._current_intrusion_w = w
        w.title("⚠ SECURITY ALERT")
        w.resizable(False, False)
        w.configure(bg="#1a1a2e")

        tf = tkfont.Font(family="Segoe UI", size=16, weight="bold")
        hf = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        bf = tkfont.Font(family="Consolas", size=9)
        sf = tkfont.Font(family="Segoe UI", size=9)

        # ── Scrollable content via Canvas ────────────────────
        canvas = tk.Canvas(w, bg="#1a1a2e", highlightthickness=0, width=560)
        scrollbar = tk.Scrollbar(w, orient="vertical", command=canvas.yview)
        content = tk.Frame(canvas, bg="#1a1a2e")

        content.bind("<Configure>",
                      lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=content, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # header (RED)
        hdr = tk.Frame(content, bg="#e74c3c", padx=15, pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="⚠  SECURITY ALERT",
                 font=tf, fg="white", bg="#e74c3c").pack()
        tk.Label(hdr, text="Suspicious network activity detected.",
                 font=sf, fg="#ffcccc", bg="#e74c3c").pack()

        # ─── Attack Details ──────────────────────────────────
        det = tk.Frame(content, bg="#16213e", padx=15, pady=10)
        det.pack(fill=tk.X, padx=10, pady=(8, 4))

        proto = (get_protocol_name(d["protocol"])
                 if isinstance(d["protocol"], (int, float))
                 else str(d["protocol"]))
        dtime = datetime.fromtimestamp(d["timestamp"]).strftime(
            "%Y-%m-%d %H:%M:%S")

        attack_type = d.get("attack_type", "Suspicious Traffic")
        risk_level  = d.get("risk_level", "Medium")
        risk_color  = RISK_COLORS.get(risk_level, "#f1c40f")

        for lbl, val, fg_c in [
            ("Attack Type", attack_type, "#ff6b6b"),
            ("Risk Level",  risk_level,  risk_color),
            ("Protocol",    proto,       "#f8f8f2"),
            ("Packet Size", f"{d['packet_size']} bytes", "#f8f8f2"),
            ("Detected At", dtime,       "#f8f8f2"),
        ]:
            r = tk.Frame(det, bg="#16213e")
            r.pack(fill=tk.X, pady=2)
            tk.Label(r, text=f"{lbl}:", font=hf, fg="#8be9fd",
                     bg="#16213e", width=14, anchor="w").pack(side=tk.LEFT)
            tk.Label(r, text=val, font=bf, fg=fg_c,
                     bg="#16213e", anchor="w").pack(side=tk.LEFT,
                                                    fill=tk.X, expand=True)

        # Confidence Score
        if "confidence" in d and d["confidence"] is not None:
            cframe = tk.Frame(det, bg="#16213e")
            cframe.pack(fill=tk.X, pady=(5, 0))
            tk.Label(cframe, text="Confidence:", font=hf,
                     fg="#94a3b8", bg="#16213e").pack(side=tk.LEFT)
            tk.Label(cframe, text=f"{d['confidence']*100:.1f}%", font=hf,
                     fg="#e74c3c", bg="#16213e").pack(side=tk.LEFT, padx=5)

        # ─── Attacker Device ─────────────────────────────────
        atk_info = d.get("attacker_info", {})
        tgt_info = d.get("target_info", {})

        devf = tk.Frame(content, bg="#1e3a5f", padx=15, pady=8)
        devf.pack(fill=tk.X, padx=10, pady=4)

        self._add_device_section(devf, "🔴 ATTACKER DEVICE", atk_info, hf, bf, "#1e3a5f")

        if tgt_info.get("ip"):
            sep = tk.Frame(devf, bg="#2c5282", height=1)
            sep.pack(fill=tk.X, pady=6)
            self._add_device_section(devf, "🟢 TARGET DEVICE", tgt_info, hf, bf, "#1e3a5f")

        # ─── Detection Explanation ───────────────────────────
        if d.get("explanation"):
            ef = tk.Frame(content, bg="#0f3460", padx=15, pady=8)
            ef.pack(fill=tk.X, padx=10, pady=4)
            tk.Label(ef, text="🔍 Detection Explanation", font=hf,
                     fg="#50fa7b", bg="#0f3460", anchor="w").pack(fill=tk.X)
            tk.Label(ef, text=d["explanation"], font=sf, fg="#f8f8f2",
                     bg="#0f3460", wraplength=520, justify=tk.LEFT,
                     anchor="w").pack(fill=tk.X, pady=(4, 0))

        # ─── Activity Summary (Last 30s) ─────────────────────
        summary_count = d.get("summary_count", 0)
        if summary_count > 0:
            sfrm = tk.Frame(content, bg="#2d3436", padx=15, pady=8)
            sfrm.pack(fill=tk.X, padx=10, pady=4)
            tk.Label(sfrm, text="📊 Intrusion Summary (Last 30 Seconds)",
                     font=hf, fg="#fab1a0", bg="#2d3436",
                     anchor="w").pack(fill=tk.X)

            top_ip    = d.get("top_ip", "Unknown")
            top_name  = d.get("top_device_name", "Unknown")
            top_vendor = d.get("top_vendor", "Unknown")
            last_atk  = d.get("last_attack_type", attack_type)
            last_risk = d.get("last_risk_level", risk_level)
            last_risk_clr = RISK_COLORS.get(last_risk, "#f1c40f")

            for lbl, val, fg_c in [
                ("Total Intrusions",  str(summary_count), "#ff6b6b"),
                ("Top Attacker IP",   top_ip,             "#f8f8f2"),
                ("Device Name",       top_name,           "#f8f8f2"),
                ("Vendor",            top_vendor,         "#f8f8f2"),
                ("Last Attack Type",  last_atk,           "#ff6b6b"),
                ("Risk Level",        last_risk,          last_risk_clr),
            ]:
                r = tk.Frame(sfrm, bg="#2d3436")
                r.pack(fill=tk.X, pady=1)
                tk.Label(r, text=f"{lbl}:", font=hf, fg="#8be9fd",
                         bg="#2d3436", width=18, anchor="w").pack(side=tk.LEFT)
                tk.Label(r, text=val, font=bf, fg=fg_c,
                         bg="#2d3436", anchor="w").pack(side=tk.LEFT,
                                                        fill=tk.X, expand=True)

        # ─── Dismiss button ─────────────────────────────────
        btf = tk.Frame(content, bg="#1a1a2e", pady=8)
        btf.pack(fill=tk.X)
        tk.Button(btf, text="Dismiss", font=hf, fg="white",
                  bg="#e74c3c", activebackground="#c0392b",
                  activeforeground="white", relief=tk.FLAT,
                  padx=30, pady=6, cursor="hand2",
                  command=w.destroy).pack()

        # Pack canvas and scrollbar
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Window sizing and centering
        w.update_idletasks()
        req_h = min(content.winfo_reqheight() + 20, 780)
        w.geometry(f"580x{req_h}")
        w.update_idletasks()
        x = (w.winfo_screenwidth() // 2) - 290
        y = (w.winfo_screenheight() // 2) - (req_h // 2)
        w.geometry(f"580x{req_h}+{x}+{y}")
        w.attributes("-topmost", True)

        w.after(30000, w.destroy)

    # ══════════════════════════════════════════════════════════
    #  2. NEW DEVICE ALERT  (YELLOW / ORANGE)
    # ══════════════════════════════════════════════════════════

    def _build_device_window(self, d):
        w = tk.Toplevel(self._root)
        w.title("📶 NEW DEVICE CONNECTED")
        w.geometry("500x420")
        w.resizable(False, False)
        w.configure(bg="#1a1a2e")
        w.update_idletasks()
        x = (w.winfo_screenwidth() // 2) - 250
        y = (w.winfo_screenheight() // 2) - 210
        w.geometry(f"500x420+{x}+{y}")
        w.attributes("-topmost", True)

        tf = tkfont.Font(family="Segoe UI", size=16, weight="bold")
        hf = tkfont.Font(family="Segoe UI", size=11, weight="bold")
        bf = tkfont.Font(family="Consolas", size=11)
        sf = tkfont.Font(family="Segoe UI", size=9)

        # header
        is_reconnect = d.get("is_reconnect", False)
        title_text = "📶 DEVICE RECONNECTED" if is_reconnect else "📶 NEW DEVICE CONNECTED"
        sub_text   = "A known device came back online" if is_reconnect else "A new device joined the WiFi network"
        hdr_bg     = "#2980b9" if is_reconnect else "#e67e22" # Blue for reconnect, Orange for new
        sub_fg     = "#d6eaf8" if is_reconnect else "#fdebd0"

        hdr = tk.Frame(w, bg=hdr_bg, padx=15, pady=12)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text=title_text,
                 font=tf, fg="white", bg=hdr_bg).pack()
        tk.Label(hdr, text=sub_text,
                 font=sf, fg=sub_fg, bg=hdr_bg).pack()

        # details
        det = tk.Frame(w, bg="#102a43", padx=20, pady=15)
        det.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        hostname    = d.get("hostname", "Unknown")
        vendor      = d.get("vendor", "Unknown Vendor")
        device_type = d.get("device_type", "Device")
        first_seen  = d.get("first_seen", "—")

        for lbl, val in [("Device Name", hostname),
                         ("IP Address", d["ip"]),
                         ("MAC Address", d["mac"]),
                         ("Vendor", vendor),
                         ("Device Type", device_type),
                         ("Connected At", first_seen)]:
            r = tk.Frame(det, bg="#102a43")
            r.pack(fill=tk.X, pady=4)
            tk.Label(r, text=f"{lbl}:", font=hf, fg="#8be9fd",
                     bg="#102a43", width=14, anchor="w").pack(side=tk.LEFT)
            tk.Label(r, text=val, font=bf, fg="#f8f8f2",
                     bg="#102a43", anchor="w").pack(side=tk.LEFT,
                                                    fill=tk.X, expand=True)

        # button (orange)
        btf = tk.Frame(w, bg="#1a1a2e", pady=10)
        btf.pack(fill=tk.X)
        tk.Button(btf, text="OK", font=hf, fg="white",
                  bg="#e67e22", activebackground="#d35400",
                  activeforeground="white", relief=tk.FLAT,
                  padx=30, pady=8, cursor="hand2",
                  command=w.destroy).pack()

        w.after(15000, w.destroy)

    # ══════════════════════════════════════════════════════════
    #  3. NETWORK STATUS ALERT  (BLUE / GREEN)
    # ══════════════════════════════════════════════════════════

    def _build_status_window(self, d):
        devices     = d.get("devices", [])
        total       = len(devices)
        scan_time   = d.get("scan_time", "—")

        row_height  = 22
        base_height = 280
        list_height = min(total, 10) * row_height
        win_h       = base_height + list_height
        win_w       = 560

        w = tk.Toplevel(self._root)
        w.title("📡 WiFi Network Status")
        w.geometry(f"{win_w}x{win_h}")
        w.resizable(False, False)
        w.configure(bg="#1a1a2e")
        w.update_idletasks()
        x = (w.winfo_screenwidth() // 2) - (win_w // 2)
        y = (w.winfo_screenheight() // 2) - (win_h // 2)
        w.geometry(f"{win_w}x{win_h}+{x}+{y}")
        w.attributes("-topmost", True)

        tf = tkfont.Font(family="Segoe UI", size=16, weight="bold")
        hf = tkfont.Font(family="Segoe UI", size=11, weight="bold")
        sf = tkfont.Font(family="Segoe UI", size=9)
        lf = tkfont.Font(family="Consolas", size=9)

        hdr = tk.Frame(w, bg="#2980b9", padx=15, pady=12)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="📡  WiFi Network Status",
                 font=tf, fg="white", bg="#2980b9").pack()
        tk.Label(hdr, text=f"Total Connected Devices: {total}",
                 font=sf, fg="#d6eaf8", bg="#2980b9").pack()

        body = tk.Frame(w, bg="#16213e", padx=15, pady=10)
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        hdr_frame = tk.Frame(body, bg="#16213e")
        hdr_frame.pack(fill=tk.X, pady=(0, 5))
        for col, cw in [("Device", 14), ("IP Address", 16),
                         ("MAC Address", 18), ("Vendor", 18)]:
            tk.Label(hdr_frame, text=col, font=sf, fg="#8be9fd",
                     bg="#16213e", width=cw, anchor="w").pack(side=tk.LEFT)

        for dev in devices[:10]:
            row = tk.Frame(body, bg="#16213e")
            row.pack(fill=tk.X)
            name = dev.get("hostname", dev.get("device_type", "Device"))
            if len(name) > 12:
                name = name[:12] + "…"
            vendor = dev.get("vendor", "Unknown")
            if len(vendor) > 16:
                vendor = vendor[:16] + "…"
            for val, cw in [(name, 14), (dev.get("ip", "?"), 16),
                             (dev.get("mac", "?"), 18), (vendor, 18)]:
                tk.Label(row, text=val, font=lf, fg="#f8f8f2",
                         bg="#16213e", width=cw, anchor="w").pack(side=tk.LEFT)

        if total > 10:
            tk.Label(body, text=f"  … and {total - 10} more devices",
                     font=sf, fg="#95a5a6", bg="#16213e",
                     anchor="w").pack(fill=tk.X, pady=(5, 0))

        ft = tk.Frame(w, bg="#1a1a2e", pady=5)
        ft.pack(fill=tk.X)
        tk.Label(ft, text=f"Last scan: {scan_time}", font=sf,
                 fg="#95a5a6", bg="#1a1a2e").pack()

        btf = tk.Frame(w, bg="#1a1a2e", pady=8)
        btf.pack(fill=tk.X)
        tk.Button(btf, text="OK", font=hf, fg="white",
                  bg="#2980b9", activebackground="#2471a3",
                  activeforeground="white", relief=tk.FLAT,
                  padx=30, pady=6, cursor="hand2",
                  command=w.destroy).pack()

        w.after(20000, w.destroy)


# ── module-level singleton ───────────────────────────────────
_mgr = AlertManager()


# ── Public API ───────────────────────────────────────────────

def show_alert(src_ip, dst_ip, protocol, packet_size,
               timestamp, explanation=None,
               attack_type="Suspicious Traffic", risk_level="Medium",
               confidence=0.0,
               summary_count=0, top_ip=None,
               attacker_info=None, target_info=None,
               top_device_name=None, top_vendor=None,
               last_attack_type=None, last_risk_level=None):
    """Thread-safe intrusion alert with device identification."""
    _mgr._q.put({
        "_type": "intrusion",
        "src_ip": str(src_ip), "dst_ip": str(dst_ip),
        "protocol": protocol, "packet_size": packet_size,
        "timestamp": timestamp, "explanation": explanation,
        "attack_type": attack_type, "risk_level": risk_level,
        "confidence": confidence,
        "summary_count": summary_count, "top_ip": top_ip,
        "attacker_info": attacker_info, "target_info": target_info,
        "top_device_name": top_device_name,
        "top_vendor": top_vendor,
        "last_attack_type": last_attack_type,
        "last_risk_level": last_risk_level,
    })
    _mgr._ensure_started()


def show_new_device_alert(ip, mac, vendor="Unknown Vendor",
                           hostname="Unknown", device_type="Device",
                           first_seen="—", is_reconnect=False):
    """Thread-safe popup for a newly discovered network device."""
    _mgr._q.put({
        "_type": "new_device",
        "ip": str(ip), "mac": str(mac),
        "vendor": str(vendor), "hostname": str(hostname),
        "device_type": str(device_type), "first_seen": str(first_seen),
        "is_reconnect": bool(is_reconnect),
    })
    _mgr._ensure_started()


def show_network_status_alert(devices, scan_time="—"):
    """Thread-safe popup showing current WiFi network status."""
    _mgr._q.put({
        "_type": "network_status",
        "devices": devices,
        "scan_time": str(scan_time),
    })
    _mgr._ensure_started()


def show_intrusion_popup(message):
    """Triggers an OS-native desktop notification using plyer."""
    try:
        from plyer import notification
        notification.notify(
            title="🚨 Intrusion Detected",
            message=message,
            app_name="AI Intrusion Detection System",
            timeout=5
        )
    except Exception as e:
        print(f"[!] Desktop Notification Failed: {e}")


# ── self-test ────────────────────────────────────────────────
if __name__ == "__main__":
    import time
    print("=== Alert System Test (3 popup types) ===")

    show_alert("192.168.1.100", "10.0.0.1", 6, 1500, time.time(),
               "Packet rate exceeds normal baseline\n"
               "Rapid connection attempts detected",
               attack_type="DoS / Packet Flood", risk_level="High",
               attacker_info={"hostname": "Redmi Note 11",
                              "ip": "192.168.1.100",
                              "mac": "40:EC:99:D1:8B:8E",
                              "vendor": "Xiaomi", "device_type": "Mobile"},
               target_info={"hostname": "Router",
                            "ip": "10.0.0.1",
                            "mac": "AA:BB:CC:DD:EE:01",
                            "vendor": "TP-Link", "device_type": "Router"},
               summary_count=14, top_ip="192.168.1.100",
               top_device_name="Redmi Note 11",
               top_vendor="Xiaomi",
               last_attack_type="DoS / Packet Flood",
               last_risk_level="High")
    time.sleep(3)

    show_new_device_alert("192.168.1.25", "40:EC:99:D1:8B:8E",
                          vendor="Xiaomi Communications",
                          hostname="Redmi-Note-11",
                          device_type="Mobile", first_seen="10:45 PM")
    time.sleep(3)

    show_network_status_alert([
        {"hostname": "Gateway", "ip": "192.168.1.1",
         "mac": "AA:BB:CC:DD:EE:01", "vendor": "TP-Link"},
        {"hostname": "Redmi-11", "ip": "192.168.1.25",
         "mac": "40:EC:99:D1:8B:8E", "vendor": "Xiaomi"},
    ], scan_time="11:45:22 PM")

    time.sleep(15)
    print("=== Done ===")
