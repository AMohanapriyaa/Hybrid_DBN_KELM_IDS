"""
main.py
-------
Entry point for the Professional AI-Based WiFi Security System.
Explainable Hybrid DBN-KELM Real-Time Intrusion Detection.

Usage:
    python main.py

Requirements:
    - Npcap installed (Windows)
    - Run as Administrator
"""

import sys
import os

# Ensure project root is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.intrusion_detection import IntrusionDetectionSystem


def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    Professional AI-Based WiFi Security System                ║
    ║    Hybrid DBN-KELM Real-Time Intrusion Detection             ║
    ║                                                              ║
    ║    Features:                                                 ║
    ║      • WiFi device discovery (ARP + hostname)                ║
    ║      • Continuous device monitoring (10s scan)               ║
    ║      • Live packet capture (Scapy)                           ║
    ║      • 15-feature extraction                                 ║
    ║      • Deep Belief Network (128→64→32→16)                    ║
    ║      • Kernel ELM hybrid classification                      ║
    ║      • Attack type classification                            ║
    ║      • Explainable AI (LIME + heuristics)                    ║
    ║      • Real-time alerts, dashboard & logging                 ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    ids = IntrusionDetectionSystem()
    ids.run()


if __name__ == "__main__":
    main()
