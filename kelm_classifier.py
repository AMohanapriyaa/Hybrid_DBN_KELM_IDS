"""
kelm_classifier.py
------------------
Kernel Extreme Learning Machine (KELM) for binary intrusion classification.

Uses an RBF kernel + analytical ridge-regression solution.
Supports hybrid scoring when combined with DBN reconstruction error.

Classes:
    0 = Normal Traffic
    1 = Intrusion / Malicious Traffic
"""

import numpy as np
from sklearn.metrics.pairwise import rbf_kernel


class KELMClassifier:
    """
    Core KELM with RBF kernel.

    Train:  output_weights = (K + I/C)^{-1} · y
    Predict:  score = K_test · output_weights
    """

    def __init__(self, gamma=0.1, regularization=1.0):
        self.gamma = gamma
        self.C = regularization
        self.X_train = None
        self.output_weights = None
        self.is_trained = False

    def _kernel(self, X1, X2):
        return rbf_kernel(X1, X2, gamma=self.gamma)

    def train(self, X, y):
        self.X_train = X.copy()
        n = X.shape[0]
        K = self._kernel(X, X) + np.eye(n) / self.C
        self.output_weights = np.linalg.solve(K, y)
        self.is_trained = True
        print(f"[*] KELM trained on {n} samples.")

    def decision_function(self, X):
        if not self.is_trained:
            raise RuntimeError("KELM not trained yet.")
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self._kernel(X, self.X_train) @ self.output_weights

    def predict(self, X):
        return (self.decision_function(X) >= 0.5).astype(int)

    def predict_proba(self, X):
        scores = self.decision_function(X)
        p1 = 1.0 / (1.0 + np.exp(-5.0 * (scores - 0.5)))
        p1 = np.clip(p1, 0.0, 1.0)
        return np.column_stack([1.0 - p1, p1])


class AnomalyKELM:
    """
    Anomaly-based wrapper around KELMClassifier.

    Trains on normal traffic (label 0) + synthetic anomalies (label 1).
    At inference, samples scoring above a learned threshold are flagged.

    Hybrid mode
    -----------
    When `hybrid_predict()` is called with a DBN reconstruction error,
    the final score is:  α · kelm_score  +  (1-α) · normalised_recon_error .
    """

    def __init__(self, gamma=0.1, regularization=1.0,
                 threshold_percentile=95, hybrid_alpha=0.6):
        self.kelm = KELMClassifier(gamma=gamma, regularization=regularization)
        self.threshold_pctile = threshold_percentile
        self.hybrid_alpha = hybrid_alpha
        self.threshold = None
        self.recon_threshold = None
        self.is_trained = False

    # ── training ─────────────────────────────────────────────
    def train(self, X_normal, recon_errors_normal=None):
        n = X_normal.shape[0]

        # synthetic anomalies
        n_syn = max(5, n // 4)
        noise = np.std(X_normal, axis=0) * 3
        idx = np.random.choice(n, n_syn, replace=True)
        X_syn = X_normal[idx] + np.random.randn(n_syn, X_normal.shape[1]) * noise

        X_all = np.vstack([X_normal, X_syn])
        y_all = np.concatenate([np.zeros(n), np.ones(n_syn)])

        self.kelm.train(X_all, y_all)

        # KELM threshold on normal traffic
        scores = self.kelm.decision_function(X_normal)
        self.threshold = np.percentile(scores, self.threshold_pctile)

        # reconstruction-error threshold (optional)
        if recon_errors_normal is not None:
            self.recon_threshold = np.percentile(
                recon_errors_normal, self.threshold_pctile)
        else:
            self.recon_threshold = None

        self.is_trained = True
        print(f"[*] Anomaly KELM threshold = {self.threshold:.4f}")

    # ── prediction ───────────────────────────────────────────
    def predict(self, X):
        if not self.is_trained:
            raise RuntimeError("AnomalyKELM not trained.")
        return (self.kelm.decision_function(X) > self.threshold).astype(int)

    def predict_proba(self, X):
        if not self.is_trained:
            raise RuntimeError("AnomalyKELM not trained.")
        return self.kelm.predict_proba(X)

    def decision_function(self, X):
        return self.kelm.decision_function(X)

    # ── hybrid scoring ───────────────────────────────────────
    def hybrid_predict(self, X, recon_errors):
        """
        Combine KELM score + DBN reconstruction error.

        Returns
        -------
        predictions : np.ndarray   (0 or 1)
        """
        if not self.is_trained:
            raise RuntimeError("AnomalyKELM not trained.")

        kelm_scores = self.kelm.decision_function(X)

        # normalise reconstruction error to [0, 1]-ish
        if self.recon_threshold and self.recon_threshold > 0:
            norm_recon = recon_errors / self.recon_threshold
        else:
            norm_recon = recon_errors

        hybrid = self.hybrid_alpha * kelm_scores + \
                 (1 - self.hybrid_alpha) * norm_recon

        hybrid_threshold = (self.hybrid_alpha * self.threshold +
                            (1 - self.hybrid_alpha) * 1.0)
        return (hybrid > hybrid_threshold).astype(int)


# ── Self-test ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== KELM Classifier Test ===")
    np.random.seed(42)

    X_n = np.random.randn(100, 16) * 0.5 + 1.0
    akelm = AnomalyKELM(gamma=0.1, regularization=1.0)
    akelm.train(X_n)

    print("Normal preds:", akelm.predict(np.random.randn(5, 16) * 0.5 + 1.0))
    print("Anomaly preds:", akelm.predict(np.random.randn(5, 16) * 5 + 10))
    print("=== Done ===")
