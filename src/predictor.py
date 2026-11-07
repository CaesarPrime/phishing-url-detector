"""
Phishing Detector
=================

Loads the trained model files and runs the complete hybrid analysis
(feature extraction -> scaling -> XGBoost -> rule engine -> hybrid decision).
"""

import json
import logging
import os

import joblib
import pandas as pd

from .feature_extraction import extract_url_features
from .hybrid_engine import hybrid_decision, label, risk_level
from .rule_engine import evaluate_security_rules

logger = logging.getLogger(__name__)

MODEL_FILE = "best_phishing_model.pkl"
SCALER_FILE = "url_scaler.pkl"
FEATURES_FILE = "feature_names.pkl"
METADATA_FILE = "model_metadata.json"


class ModelNotTrainedError(RuntimeError):
    pass


class PhishingDetector:
    def __init__(self, models_dir: str):
        paths = [os.path.join(models_dir, f) for f in (MODEL_FILE, SCALER_FILE, FEATURES_FILE)]
        missing = [p for p in paths if not os.path.exists(p)]
        if missing:
            raise ModelNotTrainedError(
                "Model files not found: " + ", ".join(missing)
                + ". Run 'python train_pipeline.py' first (see README)."
            )
        self.model = joblib.load(paths[0])
        self.scaler = joblib.load(paths[1])
        self.feature_names = joblib.load(paths[2])
        meta_path = os.path.join(models_dir, METADATA_FILE)
        self.metadata = {}
        if os.path.exists(meta_path):
            with open(meta_path, encoding="utf-8") as fh:
                self.metadata = json.load(fh)
        logger.info("Machine learning assets loaded from %s", models_dir)

    def analyze(self, url: str) -> dict:
        features = extract_url_features(url)
        frame = pd.DataFrame([features]).reindex(columns=self.feature_names, fill_value=0)
        scaled = pd.DataFrame(self.scaler.transform(frame), columns=self.feature_names)

        ml_prediction = int(self.model.predict(scaled)[0])
        probabilities = self.model.predict_proba(scaled)[0]
        confidence = float(probabilities[ml_prediction])

        risk_score, triggered_rules = evaluate_security_rules(features)
        final_prediction = hybrid_decision(ml_prediction, confidence, risk_score)

        result = {
            "url": url,
            "ml_prediction": ml_prediction,
            "prediction": final_prediction,
            "label": label(final_prediction),
            "rule_override": final_prediction != ml_prediction,
            "confidence": confidence,
            "phishing_probability": float(probabilities[1]),
            "risk_score": risk_score,
            "risk_level": risk_level(risk_score),
            "triggered_rules": triggered_rules,
            "features": features,
        }
        logger.info(
            "ML=%s | Final=%s | Confidence=%.2f%% | Risk=%s | Score=%s",
            ml_prediction, final_prediction, confidence * 100, result["risk_level"], risk_score,
        )
        return result
