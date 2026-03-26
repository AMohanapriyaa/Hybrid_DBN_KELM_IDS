"""
dbn_model.py
------------
Deep Belief Network (DBN) implemented as a deep stacked autoencoder
using TensorFlow / Keras for unsupervised feature learning.

Architecture
────────────
  Encoder: input(15) → 128 → 64 → 32 → 16   (bottleneck)
  Decoder: 16 → 32 → 64 → 128 → input(15)    (reconstruction)

After training on normal traffic the encoder transforms raw features
into a compact 16-dimensional representation.  The reconstruction
error is also used as part of the hybrid detection score.
"""

import os
import numpy as np

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"          # suppress TF noise

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model
from sklearn.preprocessing import StandardScaler
import joblib


class DBNFeatureLearner:
    """
    Deep stacked autoencoder for network traffic feature learning.

    • Trains on baseline (normal) traffic
    • transform()  → 16-D encoded representation
    • reconstruction_error()  → per-sample MSE (anomaly score)
    """

    def __init__(self, input_dim=15,
                 encoding_dims=(128, 64, 32, 16),
                 learning_rate=0.001):
        self.input_dim = input_dim
        self.encoding_dims = encoding_dims
        self.learning_rate = learning_rate
        self.scaler = StandardScaler()
        self.autoencoder = None
        self.encoder = None
        self._build_model()

    # ── Model Construction ───────────────────────────────────
    def _build_model(self):
        inp = layers.Input(shape=(self.input_dim,), name="input")
        x = inp

        # encoder
        for i, dim in enumerate(self.encoding_dims):
            x = layers.Dense(dim, activation="relu",
                             name=f"enc_{i}")(x)
            x = layers.BatchNormalization(name=f"bn_e{i}")(x)
            x = layers.Dropout(0.2, name=f"do_e{i}")(x)

        encoded = x

        # decoder (mirror)
        for i, dim in enumerate(reversed(self.encoding_dims[:-1])):
            x = layers.Dense(dim, activation="relu",
                             name=f"dec_{i}")(x)
            x = layers.BatchNormalization(name=f"bn_d{i}")(x)

        out = layers.Dense(self.input_dim, activation="linear",
                           name="output")(x)

        self.autoencoder = Model(inp, out, name="DBN_Autoencoder")
        self.autoencoder.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
            loss="mse",
        )
        self.encoder = Model(inp, encoded, name="DBN_Encoder")

    # ── Training ─────────────────────────────────────────────
    def train(self, X, epochs=50, batch_size=16, verbose=0):
        X_s = self.scaler.fit_transform(X)
        print(f"[*] Training DBN autoencoder on {X_s.shape[0]} samples "
              f"({epochs} epochs)…")
        self.autoencoder.fit(X_s, X_s,
                             epochs=epochs,
                             batch_size=batch_size,
                             shuffle=True,
                             verbose=verbose)
        print("[*] DBN training complete.")

    # ── Inference ────────────────────────────────────────────
    def transform(self, X):
        """Encode features → 16-D."""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.encoder.predict(self.scaler.transform(X), verbose=0)

    def reconstruction_error(self, X):
        """Per-sample mean-squared reconstruction error."""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        X_s = self.scaler.transform(X)
        X_r = self.autoencoder.predict(X_s, verbose=0)
        return np.mean((X_s - X_r) ** 2, axis=1)

    # ── Persistence ──────────────────────────────────────────
    def save(self, directory="models"):
        os.makedirs(directory, exist_ok=True)
        self.autoencoder.save(os.path.join(directory, "dbn_autoencoder.keras"))
        self.encoder.save(os.path.join(directory, "dbn_encoder.keras"))
        joblib.dump(self.scaler, os.path.join(directory, "dbn_scaler.pkl"))
        print(f"[*] DBN saved to '{directory}/'")

    def load(self, directory="models"):
        self.autoencoder = keras.models.load_model(
            os.path.join(directory, "dbn_autoencoder.keras"))
        self.encoder = keras.models.load_model(
            os.path.join(directory, "dbn_encoder.keras"))
        self.scaler = joblib.load(os.path.join(directory, "dbn_scaler.pkl"))
        print(f"[*] DBN loaded from '{directory}/'")


# ── Self-test ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== DBN Model Test ===")
    np.random.seed(42)
    X = np.random.rand(100, 15) * 100

    dbn = DBNFeatureLearner(input_dim=15)
    dbn.train(X, epochs=10)

    enc = dbn.transform(X[:5])
    print(f"Input  shape: {X[:5].shape}")
    print(f"Encoded shape: {enc.shape}")
    print(f"Recon errors: {dbn.reconstruction_error(X[:5])}")
    print("=== Done ===")
