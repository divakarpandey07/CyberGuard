"""
autoencoder_detector.py – Neural Autoencoder for Zero-Day Detection
FREE: Uses scikit-learn MLPRegressor, no GPU needed.

How it works:
  1. Trained ONLY on normal traffic (input → hidden → input reconstruction)
  2. Normal traffic → low reconstruction error
  3. Unknown/new attack → high reconstruction error → Zero-Day alert
"""
import os, logging
import numpy as np
import joblib
from typing import Optional

import config

logger = logging.getLogger("CyberGuard.Autoencoder")

_MODEL_PATH  = os.path.join(config.MODEL_DIR, "autoencoder.pkl")
_SCALER_PATH = os.path.join(config.MODEL_DIR, "ae_scaler.pkl")
_THRESH_PATH = os.path.join(config.MODEL_DIR, "ae_threshold.npy")


class AutoencoderDetector:
    """MLP-based autoencoder for anomaly / zero-day detection."""

    def __init__(self):
        self._model     : Optional[object] = None
        self._scaler    : Optional[object] = None
        self._threshold : float            = float("inf")
        self._loaded    = False

    # ── Load ────────────────────────────────────────────────────────────────

    def load(self) -> bool:
        try:
            if all(os.path.exists(p) for p in [_MODEL_PATH, _SCALER_PATH, _THRESH_PATH]):
                self._model     = joblib.load(_MODEL_PATH)
                self._scaler    = joblib.load(_SCALER_PATH)
                self._threshold = float(np.load(_THRESH_PATH))
                self._loaded    = True
                logger.info("✅ Autoencoder loaded  |  threshold=%.6f", self._threshold)
                return True
        except Exception as e:
            logger.warning("Autoencoder load failed: %s", e)
        return False

    # ── Train (called from train.py) ────────────────────────────────────────

    def train(self, X_normal: np.ndarray) -> None:
        """
        Train autoencoder on BENIGN samples only.
        Args:
            X_normal: raw (unscaled) feature array of normal flows
        """
        from sklearn.preprocessing   import MinMaxScaler
        from sklearn.neural_network  import MLPRegressor

        n   = len(X_normal)
        nf  = X_normal.shape[1]
        logger.info("🧠 Training Autoencoder on %d normal samples (%d features)...", n, nf)

        # Scale to [0, 1]
        self._scaler = MinMaxScaler()
        Xs = self._scaler.fit_transform(X_normal)

        # Bottleneck architecture: nf → 64 → 32 → 64 → nf
        h1, h2 = max(64, nf // 2), max(32, nf // 4)
        self._model = MLPRegressor(
            hidden_layer_sizes  = (h1, h2, h1),
            activation          = "relu",
            solver              = "adam",
            max_iter            = 150,
            early_stopping      = True,
            validation_fraction = 0.1,
            n_iter_no_change    = 10,
            random_state        = 42,
            verbose             = False,
        )
        # Autoencoder trick: target == input
        self._model.fit(Xs, Xs)

        # Compute per-sample MSE on training data
        Xr    = self._model.predict(Xs)
        errs  = np.mean((Xs - Xr) ** 2, axis=1)
        self._threshold = float(np.percentile(errs, config.AUTOENCODER_THRESHOLD_PCT))
        logger.info(
            "  MSE  mean=%.6f  std=%.6f  threshold(p%d)=%.6f",
            errs.mean(), errs.std(), config.AUTOENCODER_THRESHOLD_PCT, self._threshold
        )

        # Persist
        os.makedirs(config.MODEL_DIR, exist_ok=True)
        joblib.dump(self._model,  _MODEL_PATH)
        joblib.dump(self._scaler, _SCALER_PATH)
        np.save(_THRESH_PATH, self._threshold)
        self._loaded = True
        logger.info("✅ Autoencoder saved.")

    # ── Predict ─────────────────────────────────────────────────────────────

    def predict(self, feature_dict: dict) -> dict:
        if not self._loaded:
            return {"is_zero_day": False, "ae_error": 0.0, "ae_score": 0.0}
        try:
            vals  = [feature_dict.get(n, 0.0) for n in config.FEATURE_NAMES]
            X     = np.array(vals, dtype=np.float32).reshape(1, -1)
            Xs    = self._scaler.transform(X)
            Xr    = self._model.predict(Xs)
            err   = float(np.mean((Xs - Xr) ** 2))
            score = min(err / max(self._threshold * 2, 1e-9), 1.0)
            return {
                "is_zero_day":  err > self._threshold,
                "ae_error":     round(err, 6),
                "ae_score":     round(score, 4),
                "ae_threshold": round(self._threshold, 6),
            }
        except Exception as e:
            logger.debug("AE predict error: %s", e)
            return {"is_zero_day": False, "ae_error": 0.0, "ae_score": 0.0}

    @property
    def is_ready(self) -> bool:
        return self._loaded
