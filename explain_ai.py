"""
explain_ai.py
-------------
Explainable AI module using LIME + heuristic rules.

Provides:
    - LIME-based per-feature importance for popups
    - Rich console explanations with specific reasons
      (abnormal size, unusual port, high packet rate, etc.)
    - Baseline z-score deviation analysis
"""

import numpy as np

try:
    from lime.lime_tabular import LimeTabularExplainer
    LIME_AVAILABLE = True
except ImportError:
    LIME_AVAILABLE = False
    print("[!] WARNING: LIME not installed. Run:  pip install lime")

from src.feature_extraction import FEATURE_NAMES


# ── Known suspicious ports ───────────────────────────────────
SUSPICIOUS_PORTS = {
    23, 2323,                            # Telnet
    445, 135, 139,                       # SMB / NetBIOS
    3389,                                # RDP
    4444, 5555, 31337, 1234,             # Backdoors
    6667, 6668, 6669,                    # IRC C&C
    8080, 8443, 9090,                    # Alt HTTP
}

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


class IntrusionExplainer:
    """Explains why Network packets were flagged as intrusions."""

    def __init__(self, training_data=None):
        self.feature_names = FEATURE_NAMES
        self.class_names = ["Normal", "Intrusion"]
        self.explainer = None
        self._mean = None
        self._std = None

        if training_data is not None:
            self.set_training_data(training_data)

    # ── initialise ───────────────────────────────────────────
    def set_training_data(self, data):
        self._mean = np.mean(data, axis=0)
        self._std = np.std(data, axis=0) + 1e-8

        if not LIME_AVAILABLE:
            print("[!] LIME unavailable – using heuristic-only explanations.")
            return

        self.explainer = LimeTabularExplainer(
            training_data=data,
            feature_names=self.feature_names,
            class_names=self.class_names,
            mode="classification",
            discretize_continuous=True,
        )
        print("[*] LIME explainer initialized.")

    # ── popup explanation string ─────────────────────────────
    def explain_prediction(self, features, predict_fn, num_features=5):
        """Return combined LIME + heuristic explanation text."""
        if features.ndim == 1:
            features = features.reshape(1, -1)

        parts = []

        # LIME
        lime_txt = self._lime_text(features[0], predict_fn, num_features)
        if lime_txt:
            parts.append(lime_txt)

        # Heuristics
        h_txt = self._heuristic_text(features[0])
        if h_txt:
            parts.append(h_txt)

        return "\n".join(parts) if parts else "Traffic anomaly detected."

    # ── console explanation ──────────────────────────────────
    def console_explanation(self, features, feat_dict):
        """Print a structured Intrusion Reason block to the terminal."""
        reasons = self._reasons(features)
        proto = PROTO_NAMES.get(int(feat_dict.get("protocol", 0)),
                                f"Proto-{feat_dict.get('protocol', '?')}")

        print("  ┌─── Explainable AI Analysis ───────────────────────")
        print(f"  │  Packet : {feat_dict['src_ip']} → {feat_dict['dst_ip']}  "
              f"[{proto}, {feat_dict['packet_length']} bytes]")
        if reasons:
            print("  │")
            print("  │  Intrusion Reason:")
            for r in reasons:
                print(f"  │    • {r}")
        else:
            print("  │  ⚠ Traffic anomaly detected (deviates from baseline)")
        print("  └───────────────────────────────────────────────────")

    # ── LIME internals ───────────────────────────────────────
    def _lime_text(self, sample, predict_fn, num_features):
        if not LIME_AVAILABLE or self.explainer is None:
            return ""
        try:
            exp = self.explainer.explain_instance(
                sample, predict_fn,
                num_features=num_features, num_samples=100)
            lines = ["Top contributing factors (LIME):"]
            for rule, w in exp.as_list():
                arrow = "↑" if w > 0 else "↓"
                lines.append(f"  • {rule}: {arrow} risk ({w:+.4f})")
            return "\n".join(lines)
        except Exception as e:
            print(f"[!] LIME failed: {e}")
            return ""

    # ── heuristic internals ──────────────────────────────────
    def _heuristic_text(self, features):
        reasons = self._reasons(features)
        if not reasons:
            return ""
        return "Heuristic observations:\n" + \
               "\n".join(f"  • {r}" for r in reasons)

    def _reasons(self, f):
        """Build list of human-readable reason strings."""
        # map by name for clarity
        v = {n: f[i] for i, n in enumerate(self.feature_names) if i < len(f)}

        reasons = []

        # packet size
        pkt_len = v.get("packet_length", 0)
        if pkt_len > 1400:
            reasons.append(f"Abnormal packet size ({int(pkt_len)} bytes) "
                           "– possible data exfiltration")
        elif pkt_len < 40 and v.get("protocol", 0) == 6:
            reasons.append(f"Tiny TCP packet ({int(pkt_len)} bytes) "
                           "– possible SYN/FIN scan")

        # ports
        dp = int(v.get("dst_port", 0))
        sp = int(v.get("src_port", 0))
        if dp in SUSPICIOUS_PORTS:
            reasons.append(f"Suspicious destination port {dp}")
        if sp in SUSPICIOUS_PORTS:
            reasons.append(f"Suspicious source port {sp}")

        # protocol
        proto = int(v.get("protocol", 0))
        if proto == 1:
            reasons.append("ICMP traffic – may indicate ping sweep / ICMP tunnel")
        if proto not in (1, 6, 17):
            reasons.append(f"Unusual protocol ({proto}) – not TCP/UDP/ICMP")

        # packet rate
        rate = v.get("packet_rate", 0)
        if rate > 500:
            reasons.append(f"High packet rate ({rate:.0f} pkt/s) "
                           "– possible flood / DoS")

        # entropy
        ent = v.get("packet_entropy", 0)
        if ent > 7.5:
            reasons.append(f"High packet entropy ({ent:.2f}) "
                           "– possible encrypted / obfuscated payload")

        # timing
        td = v.get("time_delta", 0)
        if 0 < td < 0.001:
            reasons.append(f"Extremely rapid packet (Δt={td:.6f}s) "
                           "– possible packet flood")

        # TCP flags
        flags = int(v.get("tcp_flags", 0))
        if flags == 0 and proto == 6:
            reasons.append("NULL TCP flags – possible NULL scan")
        if flags == 0x29:       # FIN+PSH+URG = XMAS scan
            reasons.append("XMAS TCP flags detected – possible XMAS scan")

        # connection frequency
        cf = v.get("connection_freq", 0)
        if cf > 50:
            reasons.append(f"High connection frequency ({int(cf)} packets "
                           "to same destination)")

        # z-score baseline deviations
        if self._mean is not None:
            z = np.abs((f[:len(self._mean)] - self._mean) / self._std)
            for idx in np.where(z > 2.5)[0]:
                if idx < len(self.feature_names):
                    reasons.append(
                        f"Feature '{self.feature_names[idx]}' deviates "
                        f"{z[idx]:.1f}σ from baseline")

        return reasons

    # ── feature importance dict ──────────────────────────────
    def get_feature_importance_dict(self, features, predict_fn,
                                    num_features=5):
        if not LIME_AVAILABLE or self.explainer is None:
            return {n: 0.0 for n in self.feature_names}
        if features.ndim == 1:
            features = features.reshape(1, -1)
        try:
            exp = self.explainer.explain_instance(
                features[0], predict_fn,
                num_features=num_features, num_samples=100)
            return dict(exp.as_list())
        except Exception:
            return {n: 0.0 for n in self.feature_names}


# ── Self-test ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Explainable AI Test ===")
    np.random.seed(42)
    X = np.random.rand(50, 15) * 100

    def mock_proba(X):
        p = np.random.rand(X.shape[0], 2)
        return p / p.sum(axis=1, keepdims=True)

    ex = IntrusionExplainer(training_data=X)
    s = np.array([6, 1500, 54321, 4444, 2, 64, 20, 1460,
                  7.8, 0.0005, 2000, 5.0, 55, 80000, 1.0])
    print(ex.explain_prediction(s, mock_proba))
    ex.console_explanation(s, {
        "src_ip": "192.168.1.5", "dst_ip": "10.0.0.1",
        "protocol": 6, "packet_length": 1500})
    print("=== Done ===")
