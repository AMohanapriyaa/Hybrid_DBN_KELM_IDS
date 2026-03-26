"""
packet_capture.py
-----------------
Captures live network packets from the local machine using Scapy.

Features:
    - Continuous live sniffing with callback
    - Batch capture for baseline collection
    - Packet rate monitoring

Requirements:
    - Npcap installed on Windows (https://npcap.com)
    - Administrator privileges
"""

from scapy.all import sniff, IP


def start_capture(callback, interface=None, packet_count=0, timeout=None):
    """
    Start capturing live network packets continuously.

    Parameters
    ----------
    callback : callable
        Function called for each captured packet:  callback(packet) → None
    interface : str, optional
        Network interface to sniff on.  None = default.
    packet_count : int
        Number of packets to capture.  0 = infinite.
    timeout : int, optional
        Stop after this many seconds.
    """
    print("[*] Starting live packet capture...")
    if interface:
        print(f"[*] Sniffing on interface: {interface}")
    else:
        print("[*] Sniffing on default interface")

    try:
        sniff(
            prn=callback,
            iface=interface,
            count=packet_count,
            timeout=timeout,
            store=False,
            filter="ip",
        )
    except PermissionError:
        print("[!] ERROR: Permission denied.  Run as Administrator.")
        raise
    except Exception as e:
        print(f"[!] ERROR during packet capture: {e}")
        raise


def capture_n_packets(n, interface=None, timeout=60):
    """
    Capture exactly *n* IP packets and return them as a list.

    Parameters
    ----------
    n : int
        Number of packets to capture.
    interface : str, optional
        Network interface.
    timeout : int
        Max seconds to wait (default 60).

    Returns
    -------
    list[scapy.packet.Packet]
    """
    print(f"[*] Capturing {n} packets (timeout={timeout}s)...")
    packets = sniff(iface=interface, count=n, timeout=timeout, filter="ip")
    print(f"[*] Captured {len(packets)} packets.")
    return list(packets)


if __name__ == "__main__":
    def _print(pkt):
        if pkt.haslayer(IP):
            print(f"  {pkt[IP].src} → {pkt[IP].dst} | Proto={pkt[IP].proto} | Len={len(pkt)}")

    print("=== Packet Capture Test ===")
    start_capture(callback=_print, packet_count=10)
    print("=== Done ===")
