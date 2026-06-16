"""
online_learner.py – Incremental/Online Learning using River
FREE: pip install river
Algorithm: Hoeffding Tree (VFDT) — designed for streaming data.
Updates model in real-time without full retraining.
"""
import os, logging, threading, pickle, time
from typing import Optional

import config

logger = logging.getLogger("CyberGuard.OnlineLearner")

_MODEL_PATH = os.path.join(config.MODEL_DIR, "online_model.pkl")


class OnlineLearner:
    """
    Hoeffding Adaptive Tree for incremental learning.
    - learn_one()    : update with 1 labeled sample
    - predict_one()  : get label prediction
    Requires 100+ samples before predictions are meaningful.
    """

    def __init__(self):
        self._model     = None
        self._lock      = threading.Lock()
        self._n_trained = 0
        self._n_correct = 0
        self._ready     = False
        self._init()

    def _init(self):
        if not config.ONLINE_LEARNING_ENABLED:
            return
        try:
            from river import tree
            if os.path.exists(_MODEL_PATH):
                with open(_MODEL_PATH, "rb") as f:
                    self._model = pickle.load(f)
                logger.info("✅ Online model loaded")
            else:
                self._model = tree.HoeffdingAdaptiveTreeClassifier(
                    grace_period     = 50,
                    split_confidence = 1e-5,
                    leaf_prediction  = "nba",   # Naive Bayes Adaptive
                    seed             = 42,
                )
                logger.info("🌱 Hoeffding Adaptive Tree initialized")
            self._ready = True
        except ImportError:
            logger.warning(
                "River not installed — online learning disabled.\n"
                "  Enable with: pip install river  then set ONLINE_LEARNING_ENABLED=True"
            )

    def learn_one(self, features: dict, true_label: int) -> None:
        if not self._ready or self._model is None:
            return
        x = {k: float(features.get(k, 0.0)) for k in config.FEATURE_NAMES}
        with self._lock:
            try:
                # Track accuracy
                pred = self._model.predict_one(x)
                if pred is not None and pred == true_label:
                    self._n_correct += 1
                self._model.learn_one(x, true_label)
                self._n_trained += 1
                if self._n_trained % 500 == 0:
                    acc = self._n_correct / self._n_trained * 100
                    logger.info("Online model: %d samples | running accuracy %.1f%%",
                                self._n_trained, acc)
                    self._save()
            except Exception as e:
                logger.debug("Online learn error: %s", e)

    def predict_one(self, features: dict) -> Optional[int]:
        if not self.is_ready:
            return None
        x = {k: float(features.get(k, 0.0)) for k in config.FEATURE_NAMES}
        with self._lock:
            try:
                return self._model.predict_one(x)
            except Exception:
                return None

    def predict_proba(self, features: dict) -> dict:
        if not self.is_ready:
            return {}
        x = {k: float(features.get(k, 0.0)) for k in config.FEATURE_NAMES}
        with self._lock:
            try:
                return self._model.predict_proba_one(x) or {}
            except Exception:
                return {}

    @property
    def is_ready(self) -> bool:
        return self._ready and self._n_trained >= 100

    @property
    def n_trained(self) -> int:
        return self._n_trained

    @property
    def running_accuracy(self) -> float:
        if self._n_trained == 0:
            return 0.0
        return round(self._n_correct / self._n_trained * 100, 2)

    def get_stats(self) -> dict:
        return {
            "enabled":          self._ready,
            "n_trained":        self._n_trained,
            "running_accuracy": self.running_accuracy,
            "is_ready":         self.is_ready,
        }

    def _save(self):
        try:
            with open(_MODEL_PATH, "wb") as f:
                pickle.dump(self._model, f)
        except Exception as e:
            logger.debug("Online model save error: %s", e)
