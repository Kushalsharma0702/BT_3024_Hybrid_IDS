"""
anomaly_engine.py — IsolationForest-based anomaly detection engine.

Lifecycle:
  1. Accumulate baseline feature vectors during warmup period
  2. Train IsolationForest once min_samples threshold is reached
  3. Score new packets in real-time; emit alert candidates on anomalies
  4. Periodically retrain on rolling window to adapt to traffic drift

Design decisions:
  - sklearn IsolationForest is CPU-efficient with n_jobs=1 (avoids fork overhead)
  - Rolling deque bounds memory to O(window_size)
  - Contamination is configurable to tune false positive rate
  - Score normalization: raw IF score mapped to [0, 1] confidence
  - Model state is replaceable atomically (no lock required in single-thread)
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from ids_core.config import AnomalyConfig
from ids_core.feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    """Result from the anomaly engine for a single packet."""
    is_anomaly: bool
    confidence: float       # 0.0–1.0; higher = more anomalous
    raw_score: float        # IsolationForest decision_function output
    feature_vector: np.ndarray
    model_trained: bool     # False during warmup


class AnomalyEngine:
    """
    Adaptive anomaly detector using IsolationForest.

    Usage:
        engine = AnomalyEngine(config)
        result = engine.score(feature_vector)
        if result.is_anomaly:
            # generate alert
    """

    def __init__(self, config: AnomalyConfig, extractor: FeatureExtractor) -> None:
        self._cfg = config
        self._extractor = extractor

        # Rolling sample buffer: stores (timestamp, feature_vec)
        self._buffer: Deque[Tuple[float, np.ndarray]] = deque(
            maxlen=max(config.min_samples_to_train * 5, 2000)
        )

        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[RobustScaler] = None
        self._last_train_time: float = 0.0
        self._trained: bool = False

        # Score normalization parameters (updated each training)
        self._score_min: float = -0.5
        self._score_max: float = 0.5

        logger.info(
            "AnomalyEngine initialized. Min samples: %d, Retrain interval: %.0fs",
            config.min_samples_to_train, config.retrain_interval_seconds,
        )

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def ingest(self, feature_vec: np.ndarray) -> AnomalyResult:
        """
        Ingest a feature vector, optionally trigger retrain, and return anomaly score.
        """
        now = time.time()
        self._buffer.append((now, feature_vec.copy()))

        # Trigger initial training or periodic retrain
        self._maybe_retrain(now)

        if not self._trained:
            return AnomalyResult(
                is_anomaly=False, confidence=0.0,
                raw_score=0.0, feature_vector=feature_vec,
                model_trained=False,
            )

        return self._score(feature_vec)

    def force_retrain(self) -> bool:
        """Force immediate model retraining. Returns True on success."""
        return self._train()

    @property
    def is_trained(self) -> bool:
        return self._trained

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    # ------------------------------------------------------------------ #
    #  Training                                                            #
    # ------------------------------------------------------------------ #

    def _maybe_retrain(self, now: float) -> None:
        sufficient = len(self._buffer) >= self._cfg.min_samples_to_train
        due = (now - self._last_train_time) >= self._cfg.retrain_interval_seconds

        if sufficient and (not self._trained or due):
            self._train()

    def _train(self) -> bool:
        """Train IsolationForest on current buffer contents."""
        samples = [vec for _, vec in self._buffer]
        if len(samples) < self._cfg.min_samples_to_train:
            logger.debug("Insufficient samples for training (%d)", len(samples))
            return False

        X = np.vstack(samples).astype(np.float32)

        # Remove NaN/Inf that might result from malformed packets
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        try:
            scaler = RobustScaler()
            X_scaled = scaler.fit_transform(X)

            model = IsolationForest(
                n_estimators=self._cfg.n_estimators,
                max_samples=self._cfg.max_samples,
                contamination=self._cfg.contamination,
                random_state=self._cfg.random_state,
                n_jobs=1,   # single-threaded; avoids forking overhead
            )
            model.fit(X_scaled)

            # Compute score distribution for normalization
            scores = model.decision_function(X_scaled)
            self._score_min = float(np.percentile(scores, 1))
            self._score_max = float(np.percentile(scores, 99))

            # Atomic update
            self._model = model
            self._scaler = scaler
            self._trained = True
            self._last_train_time = time.time()

            logger.info(
                "IsolationForest retrained on %d samples. "
                "Score range [%.3f, %.3f]",
                len(samples), self._score_min, self._score_max,
            )
            return True

        except Exception as exc:
            logger.error("Training failed: %s", exc, exc_info=True)
            return False

    # ------------------------------------------------------------------ #
    #  Inference                                                           #
    # ------------------------------------------------------------------ #

    def _score(self, feature_vec: np.ndarray) -> AnomalyResult:
        assert self._model is not None and self._scaler is not None

        vec = np.nan_to_num(feature_vec, nan=0.0, posinf=0.0, neginf=0.0)
        X = vec.reshape(1, -1).astype(np.float32)

        try:
            X_scaled = self._scaler.transform(X)
            raw_score = float(self._model.decision_function(X_scaled)[0])
            pred = int(self._model.predict(X_scaled)[0])   # -1=anomaly, 1=normal
        except Exception as exc:
            logger.error("Inference error: %s", exc)
            return AnomalyResult(
                is_anomaly=False, confidence=0.0,
                raw_score=0.0, feature_vector=feature_vec,
                model_trained=True,
            )

        is_anomaly = pred == -1

        # Normalize to confidence: anomalies have negative raw_score
        # Map: score_min(most anomalous) → 1.0, score_max(most normal) → 0.0
        span = self._score_max - self._score_min
        if span > 0:
            confidence = max(0.0, min(1.0, (self._score_max - raw_score) / span))
        else:
            confidence = 1.0 if is_anomaly else 0.0

        return AnomalyResult(
            is_anomaly=is_anomaly,
            confidence=round(confidence, 4),
            raw_score=round(raw_score, 6),
            feature_vector=feature_vec,
            model_trained=True,
        )
